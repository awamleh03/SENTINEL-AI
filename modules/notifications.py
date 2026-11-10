import os
import sys
import json
import time
import smtplib
import logging
import datetime
import urllib.error
import urllib.request
from email.mime.text import MIMEText

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

from modules.database import (
    db, Site, SecurityEvent,
    NotificationChannel, NotificationLog, NotificationAggregate
)
from modules.auth import token_required

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

notifications_bp = Blueprint('notifications', __name__, url_prefix='/api')

CHANNEL_TYPES = ('email', 'slack', 'telegram', 'whatsapp')
SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
DEFAULT_PER_PAGE = 50
MAX_PER_PAGE = 200

# Required (non-secret or secret) config fields per channel type. Email may
# inherit SMTP settings from the app config, so only the recipient is required.
_REQUIRED_FIELDS = {
    'email': {'to_address'},
    'slack': {'webhook_url'},
    'telegram': {'bot_token', 'chat_id'},
    'whatsapp': {'access_token', 'phone_number_id', 'to_number'},
}
_SECRET_FIELDS = {
    'email': {'smtp_password'},
    'slack': {'webhook_url'},
    'telegram': {'bot_token'},
    'whatsapp': {'access_token'},
}


# --- helpers ----------------------------------------------------------------
def _get_owned_channel(channel_id, user_id):
    return NotificationChannel.query.filter_by(id=channel_id, user_id=user_id).first()


def _event_severity(event):
    """Derive a coarse severity from an event (best-effort, not a certainty)."""
    if event.decision == 'deny':
        return 'high'
    if event.threat_type:
        return 'medium'
    return 'low'


def _meets_severity(event, min_severity):
    return SEVERITY_ORDER.get(_event_severity(event), 0) >= SEVERITY_ORDER.get(min_severity or 'medium', 2)


def _dedup_key(event):
    return f"{event.event_type}|{event.threat_type or '-'}|{event.path or '-'}"


# --- transports -------------------------------------------------------------
def _send_email(cfg, subject, body, app):
    host = cfg.get('smtp_host') or app.config.get('ALERT_SMTP_HOST')
    port = int(cfg.get('smtp_port') or app.config.get('ALERT_SMTP_PORT') or 587)
    user = cfg.get('smtp_user') or app.config.get('ALERT_SMTP_USER')
    password = cfg.get('smtp_password') or app.config.get('ALERT_SMTP_PASSWORD')
    sender = cfg.get('smtp_from') or app.config.get('ALERT_SMTP_FROM') or user
    use_tls = cfg.get('use_tls')
    if use_tls is None:
        use_tls = app.config.get('ALERT_SMTP_USE_TLS', True)
    timeout = app.config.get('ALERT_SMTP_TIMEOUT', 10)
    to_address = cfg.get('to_address')

    if not host:
        raise RuntimeError('SMTP host is not configured')
    if not to_address:
        raise RuntimeError('recipient address is not configured')

    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = subject
    msg['From'] = sender or 'sentinel@localhost'
    msg['To'] = to_address

    with smtplib.SMTP(host, port, timeout=timeout) as server:
        if use_tls:
            server.starttls()
        if user and password:
            server.login(user, password)
        server.sendmail(msg['From'], [to_address], msg.as_string())


def _http_post_json(url, payload, timeout=10, headers=None):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/json')
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode('utf-8', errors='replace')


def _send_slack(cfg, subject, body, app):
    url = cfg.get('webhook_url')
    if not url:
        raise RuntimeError('Slack webhook URL is not configured')
    status, _ = _http_post_json(url, {'text': f'*{subject}*\n{body}'}, timeout=10)
    if status >= 300:
        raise RuntimeError(f'Slack returned HTTP {status}')


def _send_telegram(cfg, subject, body, app):
    token = cfg.get('bot_token')
    chat_id = cfg.get('chat_id')
    if not token or not chat_id:
        raise RuntimeError('Telegram bot token/chat id is not configured')
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    status, _ = _http_post_json(url, {'chat_id': chat_id, 'text': f'{subject}\n{body}'}, timeout=10)
    if status >= 300:
        raise RuntimeError(f'Telegram returned HTTP {status}')


def _send_whatsapp(cfg, subject, body, app):
    token = cfg.get('access_token')
    phone_number_id = cfg.get('phone_number_id')
    to_number = cfg.get('to_number')
    if not token or not phone_number_id or not to_number:
        raise RuntimeError('WhatsApp access token/phone number id/recipient is not configured')
    url = f'https://graph.facebook.com/v20.0/{phone_number_id}/messages'
    payload = {
        'messaging_product': 'whatsapp',
        'to': to_number,
        'type': 'text',
        'text': {'body': f'{subject}\n{body}'}
    }
    status, _ = _http_post_json(url, payload, timeout=10,
                                headers={'Authorization': f'Bearer {token}'})
    if status >= 300:
        raise RuntimeError(f'WhatsApp returned HTTP {status}')


_TRANSPORTS = {
    'email': _send_email,
    'slack': _send_slack,
    'telegram': _send_telegram,
    'whatsapp': _send_whatsapp,
}


def deliver(app, channel, subject, body):
    """Deliver a message through a channel. Returns (ok, error_message).

    Honours `NOTIFY_DRY_RUN`: when enabled, transports are not invoked and the
    call reports success without sending (used by tests).
    """
    if app.config.get('NOTIFY_DRY_RUN'):
        return True, None
    transport = _TRANSPORTS.get(channel.channel_type)
    if not transport:
        return False, f'unsupported channel type: {channel.channel_type}'
    try:
        transport(channel._parsed_config(), subject, body[:2000], app)
        return True, None
    except (smtplib.SMTPException, urllib.error.URLError, RuntimeError, OSError) as e:
        return False, str(e)
    except Exception as e:  # pragma: no cover - defensive
        return False, f'unexpected error: {e}'


# --- public operations ------------------------------------------------------
def send_system_email(app, to_address, subject, body):
    """Send a system-generated email (e.g. a password reset) using SMTP config.

    Reuses the same SMTP transport and `ALERT_SMTP_*` settings as the email
    channel. Returns (ok, error_message). Honours `NOTIFY_DRY_RUN` so tests and
    dry runs never send a real message.
    """
    if app.config.get('NOTIFY_DRY_RUN'):
        return True, None
    try:
        _send_email({'to_address': to_address}, subject, body, app)
        return True, None
    except (smtplib.SMTPException, urllib.error.URLError, RuntimeError, OSError) as e:
        return False, str(e)
    except Exception as e:  # pragma: no cover - defensive
        return False, f'unexpected error: {e}'


def test_channel(app, channel):
    """Perform a real (or dry-run) test send and update verification state."""
    now = datetime.datetime.utcnow()
    ok, error = deliver(app, channel, 'Sentinel AI test notification',
                        'This is a test notification confirming your channel is configured.')
    channel.last_tested_at = now
    if ok:
        channel.is_verified = True
        channel.last_error = None
    else:
        channel.is_verified = False
        channel.last_error = error
    db.session.add(NotificationLog(
        user_id=channel.user_id,
        site_id=channel.site_id,
        channel_id=channel.id,
        channel_type=channel.channel_type,
        status='test' if ok else 'failed',
        subject='test',
        detail=None if ok else error,
    ))
    db.session.commit()
    return ok, error


def notify_event(app, channel, event):
    """Send (or aggregate) a notification for `event` through `channel`.

    Returns the resulting NotificationLog status string.
    """
    window = app.config.get('NOTIFY_DEDUP_WINDOW_SECONDS', 300)
    key = _dedup_key(event)
    now = datetime.datetime.utcnow()

    agg = NotificationAggregate.query.filter_by(channel_id=channel.id, dedup_key=key).first()
    if agg and (now - agg.window_start).total_seconds() <= window:
        # Within the window: suppress and count, so the user is not flooded.
        agg.count += 1
        agg.last_event_id = event.id
        db.session.add(NotificationLog(
            user_id=channel.user_id, site_id=event.site_id, channel_id=channel.id,
            event_id=event.id, channel_type=channel.channel_type,
            status='aggregated', dedup_key=key,
        ))
        db.session.commit()
        return 'aggregated'

    # New window: send now, including the count of events suppressed since the
    # previous window (if any).
    suppressed = agg.count if agg else 0
    if agg:
        agg.window_start = now
        agg.count = 1
        agg.last_event_id = event.id
    else:
        agg = NotificationAggregate(channel_id=channel.id, dedup_key=key,
                                    window_start=now, count=1, last_event_id=event.id)
        db.session.add(agg)

    subject = f"[Sentinel] {event.event_type} ({_event_severity(event)})"
    body_lines = [
        f"Event: {event.event_type}",
        f"Threat: {event.threat_type or 'n/a'}",
        f"Decision: {event.decision or 'n/a'}",
        f"Action: {event.action_taken or 'n/a'}",
        f"Path: {event.method or ''} {event.path or ''}".strip(),
        f"IP: {event.ip_address or 'n/a'}",
    ]
    if suppressed:
        body_lines.append(f"(aggregated: {suppressed} similar events since the last window)")
    body = '\n'.join(body_lines)

    ok, error = deliver(app, channel, subject, body)
    db.session.add(NotificationLog(
        user_id=channel.user_id, site_id=event.site_id, channel_id=channel.id,
        event_id=event.id, channel_type=channel.channel_type,
        status='sent' if ok else 'failed', subject=subject,
        detail=None if ok else error, dedup_key=key,
    ))
    if not ok:
        channel.last_error = error
    db.session.commit()
    return 'sent' if ok else 'failed'


def dispatch_event(app, event):
    """Fan an event out to all enabled+verified channels that match its severity.

    Channels marked enabled but not yet verified are skipped: a channel is never
    treated as active before a successful test.
    """
    channels = NotificationChannel.query.filter_by(user_id=event.user_id, is_enabled=True,
                                                   is_verified=True).all()
    results = []
    for ch in channels:
        # A site-specific channel only applies to its own site; account-level
        # channels (site_id is None) apply to every site.
        if ch.site_id is not None and ch.site_id != event.site_id:
            continue
        if not _meets_severity(event, ch.min_severity):
            continue
        results.append((ch.id, notify_event(app, ch, event)))
    return results


# --- API routes -------------------------------------------------------------
@notifications_bp.route('/notifications/channels', methods=['GET'])
@token_required
def list_channels():
    query = NotificationChannel.query.filter_by(user_id=request.current_user.id)
    site_id = request.args.get('site_id', type=int)
    if site_id is not None:
        query = query.filter(NotificationChannel.site_id == site_id)
    channels = query.order_by(NotificationChannel.created_at.desc()).all()
    return jsonify({'channels': [c.to_public_dict() for c in channels]}), 200


@notifications_bp.route('/notifications/channels', methods=['POST'])
@token_required
def create_channel():
    data = request.get_json(silent=True) or {}
    channel_type = (data.get('channel_type') or '').strip()
    name = (data.get('name') or '').strip()
    config = data.get('config') or {}
    site_id = data.get('site_id')

    if channel_type not in CHANNEL_TYPES:
        return jsonify({'error': f'channel_type must be one of {CHANNEL_TYPES}'}), 400
    if not name:
        return jsonify({'error': 'name is required'}), 400
    if not isinstance(config, dict):
        return jsonify({'error': 'config must be an object'}), 400

    if site_id is not None:
        site = Site.query.filter_by(id=site_id, user_id=request.current_user.id).first()
        if not site:
            return jsonify({'error': 'Site not found'}), 404

    missing = _REQUIRED_FIELDS[channel_type] - set(config.keys())
    if missing:
        return jsonify({'error': f"missing required config fields: {sorted(missing)}"}), 400

    channel = NotificationChannel(
        user_id=request.current_user.id,
        site_id=site_id,
        channel_type=channel_type,
        name=name,
        config=json.dumps({k: v for k, v in config.items()}),
        min_severity=data.get('min_severity', 'medium'),
        is_enabled=False,
        is_verified=False,
    )
    db.session.add(channel)
    db.session.commit()
    return jsonify({'channel': channel.to_public_dict()}), 201


@notifications_bp.route('/notifications/channels/<int:channel_id>', methods=['GET'])
@token_required
def get_channel(channel_id):
    channel = _get_owned_channel(channel_id, request.current_user.id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    return jsonify({'channel': channel.to_public_dict()}), 200


@notifications_bp.route('/notifications/channels/<int:channel_id>', methods=['PATCH'])
@token_required
def update_channel(channel_id):
    channel = _get_owned_channel(channel_id, request.current_user.id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    data = request.get_json(silent=True) or {}

    if 'name' in data and str(data['name']).strip():
        channel.name = str(data['name']).strip()

    if 'min_severity' in data:
        if data['min_severity'] not in SEVERITY_ORDER:
            return jsonify({'error': 'invalid min_severity'}), 400
        channel.min_severity = data['min_severity']

    if 'config' in data:
        if not isinstance(data['config'], dict):
            return jsonify({'error': 'config must be an object'}), 400
        cfg = channel._parsed_config()
        for k, v in data['config'].items():
            # Empty secret values from the UI mean "leave unchanged".
            if k in _SECRET_FIELDS.get(channel.channel_type, set()) and (v is None or v == ''):
                continue
            cfg[k] = v
        channel.config = json.dumps(cfg)
        # Changing the configuration invalidates verification until re-tested.
        channel.is_verified = False

    if 'is_enabled' in data:
        enable = bool(data['is_enabled'])
        if enable and not channel.is_verified:
            return jsonify({'error': 'channel must be verified with a successful test before it can be enabled'}), 400
        channel.is_enabled = enable

    db.session.commit()
    return jsonify({'channel': channel.to_public_dict()}), 200


@notifications_bp.route('/notifications/channels/<int:channel_id>', methods=['DELETE'])
@token_required
def delete_channel(channel_id):
    channel = _get_owned_channel(channel_id, request.current_user.id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    NotificationAggregate.query.filter_by(channel_id=channel.id).delete(synchronize_session=False)
    NotificationLog.query.filter_by(channel_id=channel.id).update({'channel_id': None}, synchronize_session=False)
    db.session.delete(channel)
    db.session.commit()
    return jsonify({'message': 'Channel deleted'}), 200


@notifications_bp.route('/notifications/channels/<int:channel_id>/test', methods=['POST'])
@token_required
def test_channel_route(channel_id):
    channel = _get_owned_channel(channel_id, request.current_user.id)
    if not channel:
        return jsonify({'error': 'Channel not found'}), 404
    ok, error = test_channel(current_app._get_current_object(), channel)
    if ok:
        return jsonify({'message': 'Test notification sent', 'verified': True,
                        'channel': channel.to_public_dict()}), 200
    return jsonify({'error': error or 'test failed', 'verified': False,
                    'channel': channel.to_public_dict()}), 400


@notifications_bp.route('/notifications/log', methods=['GET'])
@token_required
def list_log():
    page = max(request.args.get('page', 1, type=int), 1)
    per_page = min(max(request.args.get('per_page', DEFAULT_PER_PAGE, type=int), 1), MAX_PER_PAGE)
    query = NotificationLog.query.filter_by(user_id=request.current_user.id)
    status = request.args.get('status', '').strip()
    if status:
        query = query.filter(NotificationLog.status == status)
    channel_id = request.args.get('channel_id', type=int)
    if channel_id is not None:
        query = query.filter(NotificationLog.channel_id == channel_id)
    pagination = query.order_by(NotificationLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    return jsonify({
        'logs': [item.to_dict() for item in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'pages': pagination.pages
    }), 200
