import os
import sys
import time
import math
import hashlib
import logging
from collections import deque

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

from modules.database import Site, ApiKey, record_security_event, save_alert_record
from modules.auth import load_optional_user
from modules.events import get_client_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

botguard_bp = Blueprint('botguard', __name__, url_prefix='/api')

# Paths that a rudimentary automated client is more likely to hammer.
SENSITIVE_PATH_MARKERS = (
    '/login', '/signin', '/checkout', '/payment', '/admin', '/register',
    '/reset', '/password', '/wallet', '/api/auth',
)

# Known automation markers in the User-Agent. This is only ONE weak signal
# among several — it is never decisive on its own (a legitimate crawler or a
# privacy-stripping browser can also match it).
_UA_AUTOMATION_MARKERS = (
    'bot', 'crawl', 'spider', 'scrap', 'headless', 'phantom', 'selenium',
    'puppeteer', 'playwright', 'scrapy', 'curl/', 'wget', 'python-requests',
    'python-urllib', 'go-http-client', 'java/', 'okhttp', 'libwww',
    'httpclient', 'axios/', 'node-fetch', 'guzzle', 'postman',
)

# In-process behavioural tracker keyed by an opaque one-way identity hash.
# This state is per instance (it is NOT shared across replicas), never stores a
# raw IP/API key, and is used only to *raise suspicion* — never to block.
_BURST = {}
_BURST_MAX_KEYS = 5000
_BURST_MAX_SAMPLES = 120

# In-process dedupe for dashboard Alert creation (per process). Prevents flooding
# the Alerts tab when the same identity repeatedly scores as suspicious.
_ALERT_DEDUP = {}
_ALERT_DEDUP_TTL = 300  # seconds


def _pepper() -> str:
    return current_app.config.get('SENTINEL_API_KEY_PEPPER', '') or ''


def _identity_hash(site_id, ip, api_key) -> str:
    """One-way identity for the behavioural tracker — no raw IP is retained."""
    if api_key is not None:
        material = f'botguard:{site_id}:apikey:{api_key.id}'
    else:
        material = f'botguard:{site_id}:ip:{ip or "unknown"}'
    return hashlib.sha256((_pepper() + material).encode('utf-8')).hexdigest()


def _resolve_api_key(raw_key):
    """Resolve an X-API-Key to its active ApiKey row, or None."""
    if not raw_key:
        return None
    key_hash = hashlib.sha256((_pepper() + raw_key).encode('utf-8')).hexdigest()
    api_key = ApiKey.query.filter_by(key_hash=key_hash).first()
    if not api_key or not api_key.is_active:
        return None
    site = Site.query.get(api_key.site_id)
    if not site or not site.is_active:
        return None
    return api_key


def _collect_timestamps(identity_hash):
    """Record this request and return (now, recent timestamps) for the identity."""
    now = time.time()
    bucket = _BURST.get(identity_hash)
    if bucket is None:
        if len(_BURST) >= _BURST_MAX_KEYS:
            # Simple bound; the state is non-authoritative and safe to drop.
            _BURST.clear()
        bucket = deque(maxlen=_BURST_MAX_SAMPLES)
        _BURST[identity_hash] = bucket
    bucket.append(now)
    cutoff = now - 60
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    return now, list(bucket)


def _behavioural_signals(identity_hash):
    """Return (high_rate, too_regular) booleans and the count in the window."""
    cfg = current_app.config
    now, stamps = _collect_timestamps(identity_hash)

    window = cfg.get('BOT_WINDOW_SECONDS', 10)
    count_in_window = sum(1 for ts in stamps if ts >= now - window)
    high_rate = count_in_window >= cfg.get('BOT_RATE_THRESHOLD', 20)

    intervals = [round((stamps[i] - stamps[i - 1]) * 1000.0, 3) for i in range(1, len(stamps))]
    intervals = intervals[-(cfg.get('BOT_INTERVAL_SAMPLE_LIMIT', 20)):]
    too_regular = False
    min_samples = cfg.get('BOT_INTERVAL_MIN_SAMPLES', 6)
    if len(intervals) >= min_samples:
        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stdev = math.sqrt(variance)
        # Machine-paced clients fire at near-constant intervals with low jitter.
        if 50.0 <= mean <= 5000.0 and stdev <= cfg.get('BOT_INTERVAL_MAX_STDEV_MS', 50.0):
            too_regular = True

    return high_rate, too_regular, count_in_window


def evaluate_bot(site, api_key, ip, headers, path=None, method=None, user_id=None):
    """Score a request for *suspected* automated behaviour (monitor-only).

    The score is the sum of several weak signals; no single signal is decisive
    and the result is always a heuristic suspicion, never a confirmed fact. This
    phase never blocks: the returned `action_taken` is always 'monitored' and
    `allowed` is never False. Must run in an application context.
    """
    cfg = current_app.config
    score = 0
    signals = []

    def add(code, weight):
        nonlocal score
        score += weight
        signals.append({'code': code, 'weight': weight})

    ua = (headers.get('User-Agent') or '').strip()
    accept_language = (headers.get('Accept-Language') or '').strip()
    accept = (headers.get('Accept') or '').strip()
    referer = (headers.get('Referer') or '').strip()
    path_l = (path or '').lower()

    # --- header shape (weak signals) ---
    if not ua:
        add('missing_user_agent', 15)
    else:
        ua_l = ua.lower()
        if any(marker in ua_l for marker in _UA_AUTOMATION_MARKERS):
            add('automation_marker_in_user_agent', 20)
        elif len(ua) < 20:
            add('unusually_short_user_agent', 8)

    if not accept_language:
        add('missing_accept_language', 10)
    if not accept:
        add('missing_accept_header', 12)
    elif accept == '*/*':
        add('generic_accept_header', 6)

    # --- request target ---
    if any(marker in path_l for marker in SENSITIVE_PATH_MARKERS):
        add('sensitive_path_targeted', 10)
        if not referer and method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            add('missing_referer_on_sensitive_path', 8)

    # --- behaviour over time (per instance, in-memory) ---
    identity = _identity_hash(site.id, ip, api_key)
    high_rate, too_regular, count_in_window = _behavioural_signals(identity)
    if high_rate:
        add('high_request_rate', 25)
    if too_regular:
        add('too_regular_intervals', 20)

    score = min(score, 100)
    threshold = cfg.get('BOT_SUSPICION_THRESHOLD', 40)
    suspicious = score >= threshold
    if score >= 70:
        level = 'high'
    elif suspicious:
        level = 'medium'
    elif score > 0:
        level = 'low'
    else:
        level = 'none'

    result = {
        'score': score,
        'confidence': round(score / 100.0, 2),
        'level': level,
        'suspicious': suspicious,
        'reasons': [s['code'] for s in signals],
        'signals': signals,
        # Separation of verdict vs. enforced action: the detection verdict is a
        # suspicion, the enforced action is always observation in this phase.
        'decision': 'suspicious' if suspicious else 'allow',
        'action_taken': 'monitored',
        'monitor_only': True,
        'requests_in_window': count_in_window,
        'note': 'Heuristic suspicion only — not a confirmed bot.',
    }

    if suspicious:
        _record_bot_event(site, user_id, ip, path, method, result, identity)
    return result


def _should_raise_dashboard_alert(identity, level):
    """Return True if a dashboard Alert may be created for this identity/level.

    Dedup is best-effort and per-process only; it is not a hard guarantee across
    replicas. Medium/high only — low scores never create Alerts.
    """
    if level not in ('medium', 'high'):
        return False
    now = time.time()
    # Drop expired entries opportunistically.
    expired = [k for k, ts in _ALERT_DEDUP.items() if now - ts > _ALERT_DEDUP_TTL]
    for k in expired:
        _ALERT_DEDUP.pop(k, None)
    key = f'{identity}:{level}'
    last = _ALERT_DEDUP.get(key)
    if last is not None and (now - last) < _ALERT_DEDUP_TTL:
        return False
    _ALERT_DEDUP[key] = now
    return True


def _record_bot_event(site, user_id, ip, path, method, result, identity=None):
    """Persist a bot-suspicion event (best-effort) and optionally a dashboard Alert."""
    try:
        record_security_event(
            current_app._get_current_object(),
            event_type='bot_suspected',
            threat_type='suspected_automation',
            user_id=user_id,
            site_id=site.id,
            method=method,
            path=path,
            ip_address=ip,
            decision=result['decision'],
            action_taken=result['action_taken'],
            confidence=result['confidence'],
            details={
                'score': result['score'],
                'level': result['level'],
                'reasons': result['reasons'],
                'signals': result['signals'],
                'requests_in_window': result['requests_in_window'],
            },
        )
    except Exception:
        logger.exception('Failed to record bot suspicion event')

    # Dashboard Alert: medium/high only, monitor-only, with simple flood control.
    try:
        level = result.get('level')
        if identity is None:
            identity = f'site:{site.id}'
        if not _should_raise_dashboard_alert(identity, level):
            return
        severity = 'high' if level == 'high' else 'medium'
        reasons = result.get('reasons') or []
        reason_txt = ', '.join(reasons[:6]) if reasons else 'heuristic signals'
        title = f'BotGuard: {level} suspicion'
        message = (
            f'Suspected automation (score={result.get("score")}, '
            f'path={(method or "")} {(path or "")}). Reasons: {reason_txt}. '
            f'Monitor only — not blocked.'
        )
        save_alert_record(
            current_app._get_current_object(),
            user_id=user_id,
            source='botguard',
            severity=severity,
            title=title,
            message=message,
            alert_metadata={
                'score': result.get('score'),
                'level': level,
                'reasons': reasons,
                'path': path,
                'method': method,
                'monitor_only': True,
            },
            site_id=site.id,
        )
    except Exception:
        logger.exception('Failed to create botguard dashboard alert')


def _read_header(headers, overrides, name):
    """Case-insensitive header lookup with caller-supplied overrides winning."""
    for key in (name, name.lower()):
        value = overrides.get(key)
        if value is not None:
            return value
    return headers.get(name) or ''


@botguard_bp.route('/botguard/evaluate', methods=['POST'])
def evaluate_endpoint():
    """Score a request for suspected automation (monitor-only, never blocks).

    Authenticable either by a dashboard bearer token (with `site_id` in the
    body) or by an SDK `X-API-Key` header. An SDK proxy may forward the end
    user's header values via `headers` in the body; these override the headers
    of this request. The client IP is resolved via the trusted-proxy config.
    """
    data = request.get_json(silent=True) or {}
    path = (data.get('path') or '').strip() or None
    method = (data.get('method') or 'GET').strip().upper()
    ip = get_client_ip()

    overrides = data.get('headers') or {}
    if not isinstance(overrides, dict):
        overrides = {}
    headers = {
        name: _read_header(request.headers, overrides, name)
        for name in ('User-Agent', 'Accept-Language', 'Accept', 'Referer')
    }

    api_key = _resolve_api_key(request.headers.get('X-API-Key'))
    if api_key is not None:
        site = Site.query.get(api_key.site_id)
        user_id = api_key.user_id
    else:
        user = load_optional_user()
        if user is None:
            return jsonify({'error': 'Authorization token or X-API-Key is required'}), 401
        try:
            site_id = int(data.get('site_id'))
        except (TypeError, ValueError):
            return jsonify({'error': 'site_id is required'}), 400
        site = Site.query.filter_by(id=site_id, user_id=user.id).first()
        if not site:
            return jsonify({'error': 'Site not found'}), 404
        user_id = user.id

    result = evaluate_bot(site, api_key, ip, headers, path=path, method=method, user_id=user_id)
    return jsonify({'result': result}), 200
