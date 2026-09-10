import os
import sys
import logging
import time
import datetime
from collections import deque
from statistics import mean, stdev

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

try:
    import psutil
except ImportError:
    psutil = None

from modules.database import save_scan_record, save_alert_record

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

sysguard_bp = Blueprint('sysguard', __name__, url_prefix='/api/sysguard')

_HISTORY = {
    'cpu': deque(maxlen=60),
    'memory': deque(maxlen=60),
    'disk': deque(maxlen=60),
    'network_io': deque(maxlen=60),
    'timestamps': deque(maxlen=60)
}
_LAST_NET = None


def _detect_anomaly(values, current, threshold_std=2.0):
    if len(values) < 10:
        return False, None, None, 'insufficient_data'
    try:
        avg = mean(values)
        sd = stdev(values) if len(values) > 1 else 0.0
        if sd == 0:
            return abs(current - avg) > 0 and current > 85, avg, 0, 'no_variance'
        z = (current - avg) / sd
        return z > threshold_std or (current > 95 and avg < 80), avg, sd, z
    except Exception as e:
        logger.warning(f"Anomaly detection error: {str(e)}")
        return False, None, None, 'error'


def _get_network_bytes():
    if not psutil:
        return None
    try:
        counters = psutil.net_io_counters()
        return counters.bytes_sent + counters.bytes_recv
    except Exception:
        return None


def get_system_status(history_window=20):
    global _LAST_NET
    result = {
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'available': psutil is not None,
        'cpu': {},
        'memory': {},
        'disk': {},
        'network': {},
        'anomalies': [],
        'alerts': []
    }
    if psutil is None:
        result['error'] = 'psutil library is not installed or not available'
        return result
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_count = psutil.cpu_count(logical=True)
        cpu_freq = None
        try:
            freq = psutil.cpu_freq()
            if freq:
                cpu_freq = {'current': freq.current, 'min': freq.min, 'max': freq.max}
        except Exception:
            pass
        per_cpu = psutil.cpu_percent(interval=None, percpu=True)
        result['cpu'] = {
            'percent': round(cpu_percent, 2),
            'count_logical': cpu_count,
            'count_physical': psutil.cpu_count(logical=False),
            'frequency': cpu_freq,
            'per_cpu_percent': [round(x, 2) for x in per_cpu]
        }
        cpu_anom, cpu_avg, cpu_sd, cpu_meta = _detect_anomaly(list(_HISTORY['cpu'])[-history_window:], cpu_percent)
        result['cpu']['baseline'] = {
            'average': round(cpu_avg, 2) if cpu_avg is not None else None,
            'stddev': round(cpu_sd, 2) if cpu_sd is not None else None,
            'z_score': round(cpu_meta, 3) if isinstance(cpu_meta, (int, float)) else cpu_meta
        }
        if cpu_anom:
            result['anomalies'].append({'type': 'cpu', 'value': cpu_percent,
                                        'message': 'CPU usage spike detected'})
            result['alerts'].append({'severity': 'medium' if cpu_percent < 90 else 'high',
                                     'title': 'CPU anomaly',
                                     'detail': f'CPU at {cpu_percent}% vs avg {round(cpu_avg, 1) if cpu_avg else "?"}%'})
        _HISTORY['cpu'].append(cpu_percent)
    except Exception as e:
        logger.error(f"SysGuard CPU read error: {str(e)}")
        result['cpu'] = {'error': str(e)[:200]}

    try:
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
        result['memory'] = {
            'total_gb': round(mem.total / (1024 ** 3), 2),
            'available_gb': round(mem.available / (1024 ** 3), 2),
            'used_gb': round(mem.used / (1024 ** 3), 2),
            'percent': round(mem_percent, 2),
            'buffers_gb': round(getattr(mem, 'buffers', 0) / (1024 ** 3), 2),
            'cached_gb': round(getattr(mem, 'cached', 0) / (1024 ** 3), 2)
        }
        try:
            swap = psutil.swap_memory()
            result['memory']['swap'] = {
                'total_gb': round(swap.total / (1024 ** 3), 2),
                'used_gb': round(swap.used / (1024 ** 3), 2),
                'percent': round(swap.percent, 2)
            }
        except Exception:
            pass
        mem_anom, mem_avg, mem_sd, mem_meta = _detect_anomaly(list(_HISTORY['memory'])[-history_window:], mem_percent)
        result['memory']['baseline'] = {
            'average': round(mem_avg, 2) if mem_avg is not None else None,
            'stddev': round(mem_sd, 2) if mem_sd is not None else None,
            'z_score': round(mem_meta, 3) if isinstance(mem_meta, (int, float)) else mem_meta
        }
        if mem_anom or mem_percent > 90:
            msg = 'Memory usage critically high' if mem_percent > 90 else 'Memory anomaly detected'
            result['anomalies'].append({'type': 'memory', 'value': mem_percent, 'message': msg})
            result['alerts'].append({'severity': 'high' if mem_percent > 90 else 'medium',
                                     'title': 'Memory alert',
                                     'detail': f'Memory at {mem_percent}%'})
        _HISTORY['memory'].append(mem_percent)
    except Exception as e:
        logger.error(f"SysGuard memory error: {str(e)}")
        result['memory'] = {'error': str(e)[:200]}

    try:
        disk_parts = psutil.disk_partitions(all=False)
        disk_usage = []
        for part in disk_parts:
            try:
                du = psutil.disk_usage(part.mountpoint)
                disk_usage.append({
                    'device': part.device,
                    'mountpoint': part.mountpoint,
                    'fstype': part.fstype,
                    'total_gb': round(du.total / (1024 ** 3), 2),
                    'used_gb': round(du.used / (1024 ** 3), 2),
                    'free_gb': round(du.free / (1024 ** 3), 2),
                    'percent': round(du.percent, 2)
                })
            except PermissionError:
                continue
        overall_percent = max((d['percent'] for d in disk_usage), default=0)
        result['disk'] = {
            'partitions': disk_usage,
            'max_used_percent': round(overall_percent, 2)
        }
        disk_anom, disk_avg, disk_sd, disk_meta = _detect_anomaly(list(_HISTORY['disk'])[-history_window:], overall_percent)
        result['disk']['baseline'] = {
            'average': round(disk_avg, 2) if disk_avg is not None else None,
            'stddev': round(disk_sd, 2) if disk_sd is not None else None
        }
        for d in disk_usage:
            if d['percent'] > 90:
                result['anomalies'].append({'type': 'disk', 'value': d['percent'],
                                            'message': f'Disk nearly full: {d["mountpoint"]}'})
                result['alerts'].append({'severity': 'high',
                                         'title': 'Disk nearly full',
                                         'detail': f'{d["mountpoint"]} at {d["percent"]}%'})
        _HISTORY['disk'].append(overall_percent)
    except Exception as e:
        logger.error(f"SysGuard disk error: {str(e)}")
        result['disk'] = {'error': str(e)[:200]}

    try:
        current_net = _get_network_bytes()
        delta_bytes_per_sec = 0
        delta_KBps = 0
        prev = _LAST_NET
        if prev is not None and current_net is not None:
            delta_bytes_per_sec = max(0, (current_net - prev['bytes']) / max(0.1, time.time() - prev['ts']))
            delta_KBps = delta_bytes_per_sec / 1024
        _LAST_NET = {'bytes': current_net, 'ts': time.time()} if current_net is not None else _LAST_NET
        net_io_counters = None
        try:
            nic = psutil.net_io_counters()
            net_io_counters = {
                'bytes_sent': nic.bytes_sent,
                'bytes_recv': nic.bytes_recv,
                'packets_sent': nic.packets_sent,
                'packets_recv': nic.packets_recv,
                'errin': nic.errin,
                'errout': nic.errout,
                'dropin': nic.dropin,
                'dropout': nic.dropout
            }
        except Exception:
            pass
        result['network'] = {
            'throughput_KBps': round(delta_KBps, 2),
            'connections_count': len(psutil.net_connections(kind='inet')),
            'io_counters': net_io_counters
        }
        try:
            if_addrs = psutil.net_if_addrs()
            result['network']['interfaces'] = {
                ifname: [{'family': str(addr.family),
                          'address': addr.address,
                          'netmask': addr.netmask} for addr in addrs]
                for ifname, addrs in if_addrs.items()
            }
        except Exception:
            pass
        net_anom, net_avg, net_sd, net_meta = _detect_anomaly(list(_HISTORY['network_io'])[-history_window:], delta_KBps)
        result['network']['baseline'] = {
            'average_KBps': round(net_avg, 2) if net_avg is not None else None,
            'stddev_KBps': round(net_sd, 2) if net_sd is not None else None,
            'z_score': round(net_meta, 3) if isinstance(net_meta, (int, float)) else net_meta
        }
        if net_anom and delta_KBps > 1000:
            result['anomalies'].append({'type': 'network', 'value': round(delta_KBps, 2),
                                        'message': 'Unusual network throughput spike'})
            result['alerts'].append({'severity': 'medium',
                                     'title': 'Network anomaly',
                                     'detail': f'Throughput at {round(delta_KBps / 1024, 2)} MB/s'})
        _HISTORY['network_io'].append(delta_KBps)
    except Exception as e:
        logger.error(f"SysGuard network error: {str(e)}")
        result['network'] = {'error': str(e)[:200]}

    try:
        boot = psutil.boot_time()
        result['uptime_seconds'] = round(time.time() - boot, 0)
        result['boot_time'] = datetime.datetime.fromtimestamp(boot).isoformat()
    except Exception:
        pass

    try:
        result['process_count'] = len(psutil.pids())
    except Exception:
        pass

    try:
        top = []
        for proc in sorted(psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']),
                           key=lambda p: (p.info.get('cpu_percent') or 0), reverse=True)[:5]:
            try:
                top.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'user': proc.info.get('username'),
                    'cpu_percent': round(proc.info.get('cpu_percent') or 0, 2),
                    'memory_percent': round(proc.info.get('memory_percent') or 0, 2)
                })
            except Exception:
                continue
        result['top_processes'] = top
    except Exception:
        result['top_processes'] = []

    _HISTORY['timestamps'].append(time.time())

    risk_score = 0.0
    if psutil is not None:
        c = result['cpu'].get('percent', 0) or 0
        m = result['memory'].get('percent', 0) or 0
        d = result['disk'].get('max_used_percent', 0) or 0
        risk_score = (c * 0.3 + m * 0.4 + d * 0.3)
        if len(result['anomalies']) > 0:
            risk_score += len(result['anomalies']) * 10
        risk_score = min(round(risk_score, 2), 100)
    result['risk_score'] = risk_score
    result['risk_level'] = 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 15 else 'low'
    result['history_size'] = len(_HISTORY['timestamps'])
    return result


@sysguard_bp.route('/status', methods=['GET'])
def status():
    try:
        result = get_system_status()
        user_id = getattr(request, 'current_user', None)
        user_id = user_id.id if user_id else None
        if user_id and result['risk_score'] >= 40:
            save_scan_record(
                current_app._get_current_object(),
                user_id=user_id,
                module='sysguard',
                target='system_status',
                risk_score=result['risk_score'],
                details=result,
                raw_input_size=None
            )
        for a in result.get('alerts', []):
            if a.get('severity') in ('high', 'critical'):
                save_alert_record(
                    current_app._get_current_object(),
                    user_id=user_id,
                    source='sysguard',
                    severity=a.get('severity', 'medium'),
                    title=a.get('title', 'System alert'),
                    message=a.get('detail', '')
                )
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"SysGuard status endpoint error: {str(e)}")
        return jsonify({'error': f'System status failed: {str(e)[:200]}'}), 500


@sysguard_bp.route('/history', methods=['GET'])
def history():
    try:
        limit = min(int(request.args.get('limit', 30)), 60)
        data = {
            'timestamps': [datetime.datetime.fromtimestamp(t).isoformat() for t in list(_HISTORY['timestamps'])[-limit:]],
            'cpu': list(_HISTORY['cpu'])[-limit:],
            'memory': list(_HISTORY['memory'])[-limit:],
            'disk': list(_HISTORY['disk'])[-limit:],
            'network_KBps': list(_HISTORY['network_io'])[-limit:],
            'count': min(len(_HISTORY['timestamps']), limit)
        }
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"SysGuard history error: {str(e)}")
        return jsonify({'error': str(e)[:200]}), 500


@sysguard_bp.route('/processes', methods=['GET'])
def processes():
    try:
        if not psutil:
            return jsonify({'error': 'psutil not available'}), 503
        limit = min(int(request.args.get('limit', 50)), 200)
        sort_by = request.args.get('sort', 'cpu')
        procs = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent',
                                          'memory_info', 'create_time', 'status']):
            try:
                info = proc.info
                mem_info = info.get('memory_info')
                procs.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'user': info.get('username'),
                    'cpu_percent': round(info.get('cpu_percent') or 0, 2),
                    'memory_percent': round(info.get('memory_percent') or 0, 2),
                    'rss_mb': round((mem_info.rss / (1024 * 1024)), 2) if mem_info and hasattr(mem_info, 'rss') else None,
                    'vms_mb': round((mem_info.vms / (1024 * 1024)), 2) if mem_info and hasattr(mem_info, 'vms') else None,
                    'started': datetime.datetime.fromtimestamp(info['create_time']).isoformat() if info.get('create_time') else None,
                    'status': info.get('status')
                })
            except Exception:
                continue
        if sort_by == 'memory':
            procs.sort(key=lambda x: x['memory_percent'], reverse=True)
        else:
            procs.sort(key=lambda x: x['cpu_percent'], reverse=True)
        return jsonify({'total': len(procs), 'processes': procs[:limit]}), 200
    except Exception as e:
        logger.error(f"SysGuard processes error: {str(e)}")
        return jsonify({'error': str(e)[:200]}), 500
