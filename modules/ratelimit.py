import os
import sys
import time
import hashlib
import logging
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app
from sqlalchemy.exc import IntegrityError

from modules.database import (
    db, Site, ApiKey, RateLimitRule, RateLimitCounter, record_security_event,
    RATE_LIMIT_SCOPES, RATE_LIMIT_ACTIONS,
)
from modules.auth import token_required, load_optional_user
from modules.events import get_client_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ratelimit_bp = Blueprint('ratelimit', __name__, url_prefix='/api')

MAX_NAME_LEN = 120
MAX_LIMIT = 1_000_000
MAX_WINDOW = 86_400


# --- helpers -----------------------------------------------------------------

def _get_owned_site(site_id, user):
    """Fetch a site owned by `user`, or None (per-account isolation)."""
    return Site.query.filter_by(id=site_id, user_id=user.id).first()


def _get_owned_rule(rule_id, user):
    return RateLimitRule.query.filter_by(id=rule_id, user_id=user.id).first()


def _pepper() -> str:
    return current_app.config.get('SENTINEL_API_KEY_PEPPER', '') or ''


def _hash_key(raw_key: str) -> str:
    """Same hashing scheme as modules.sites so SDK keys validate identically."""
    return hashlib.sha256((_pepper() + raw_key).encode('utf-8')).hexdigest()


def _resolve_api_key(raw_key):
    """Resolve an X-API-Key to its active ApiKey row, or None."""
    if not raw_key:
        return None
    api_key = ApiKey.query.filter_by(key_hash=_hash_key(raw_key)).first()
    if not api_key or not api_key.is_active:
        return None
    site = Site.query.get(api_key.site_id)
    if not site or not site.is_active:
        return None
    return api_key


def _counter_key(site_id, scope, identity) -> str:
    """One-way key for a counter row — the raw IP / API key is never stored."""
    material = f'ratelimit:{site_id}:{scope}:{identity}'
    return hashlib.sha256((_pepper() + material).encode('utf-8')).hexdigest()


def _select_rule(site_id, scope):
    """The highest-priority enabled rule for a site + scope, or None."""
    return RateLimitRule.query.filter_by(
        site_id=site_id, scope=scope, is_enabled=True
    ).order_by(RateLimitRule.priority.desc(), RateLimitRule.id.asc()).first()


def _increment(site_id, scope, key_hash, window_seconds, now_epoch):
    """Atomically bump the fixed-window counter and return (count, window_start).

    A single conditional UPDATE keeps the increment atomic across instances; if
    the row does not exist yet it is inserted, and an insert race is resolved by
    retrying the UPDATE after an IntegrityError.
    """
    window_start = datetime.utcfromtimestamp(now_epoch - (now_epoch % window_seconds))
    now = datetime.utcfromtimestamp(now_epoch)
    filt = dict(site_id=site_id, scope=scope, key_hash=key_hash, window_start=window_start)

    updated = db.session.query(RateLimitCounter).filter_by(**filt).update(
        {'count': RateLimitCounter.count + 1, 'updated_at': now},
        synchronize_session=False,
    )
    if not updated:
        db.session.add(RateLimitCounter(count=1, updated_at=now, **filt))
    try:
        db.session.commit()
    except IntegrityError:
        # Another instance inserted the same window row first; retry the bump.
        db.session.rollback()
        db.session.query(RateLimitCounter).filter_by(**filt).update(
            {'count': RateLimitCounter.count + 1, 'updated_at': now},
            synchronize_session=False,
        )
        db.session.commit()

    counter = RateLimitCounter.query.filter_by(**filt).first()
    return (counter.count if counter else 1), window_start


def _record_violation(site, user_id, ip, rule, result):
    """Persist a security event for an over-limit request (best-effort)."""
    try:
        record_security_event(
            current_app._get_current_object(),
            event_type='rate_limit',
            threat_type='rate_limit_exceeded',
            user_id=user_id,
            site_id=site.id,
            method=request.method,
            path=request.path,
            ip_address=ip,
            # Detection verdict vs. the action actually enforced.
            decision=result['decision'],
            action_taken=result['action_taken'],
            rule_id=str(rule.id),
            details={
                'scope': result['scope'],
                'limit': result['limit'],
                'window_seconds': result['window_seconds'],
                'count': result['count'],
                'retry_after': result['retry_after'],
                'rule_name': rule.name,
            },
        )
    except Exception:
        logger.exception('Failed to record rate limit event')


def evaluate_rate_limit(site, api_key, ip, path=None, method=None, user_id=None):
    """Check a request against a site's rate limit rules.

    The identity dimension is the API key when one was supplied, otherwise the
    client IP. Returns a plain dict; `allowed` is False only when the request is
    over the limit *and* the matching rule's action is 'block' — a 'monitor'
    rule always returns allowed=True. Must run in an application context.
    """
    scope_pref = 'api_key' if api_key is not None else 'ip'
    rule = _select_rule(site.id, scope_pref)
    if rule is None and scope_pref == 'api_key':
        rule = _select_rule(site.id, 'ip')
    if rule is None:
        return {
            'allowed': True,
            'limited': False,
            'scope': None,
            'rule_id': None,
            'rule_name': None,
            'limit': None,
            'window_seconds': None,
            'count': None,
            'remaining': None,
            'retry_after': None,
            'window_start': None,
            'decision': 'allow',
            'action_taken': 'allowed',
            'reason': 'no_matching_rule',
        }

    scope = rule.scope
    if scope == 'api_key':
        identity = f'apikey:{api_key.id}'
    else:
        identity = f'ip:{ip or "unknown"}'
    key_hash = _counter_key(site.id, scope, identity)

    now_epoch = int(time.time())
    count, window_start = _increment(site.id, scope, key_hash, rule.window_seconds, now_epoch)

    exceeded = count > rule.limit_count
    retry_after = rule.window_seconds - (now_epoch % rule.window_seconds)

    if exceeded:
        decision = 'block'
        action_taken = 'blocked' if rule.action == 'block' else 'monitored'
    else:
        decision = 'allow'
        action_taken = 'allowed'

    allowed = not (exceeded and rule.action == 'block')
    result = {
        'allowed': allowed,
        'limited': exceeded,
        'scope': scope,
        'rule_id': rule.id,
        'rule_name': rule.name,
        'limit': rule.limit_count,
        'window_seconds': rule.window_seconds,
        'count': count,
        'remaining': max(0, rule.limit_count - count),
        'retry_after': retry_after if exceeded else 0,
        'window_start': window_start.isoformat(),
        'decision': decision,
        'action_taken': action_taken,
        'reason': 'rule_block' if (exceeded and rule.action == 'block')
                  else ('rule_monitor' if exceeded else 'under_limit'),
    }
    if exceeded:
        _record_violation(site, user_id, ip, rule, result)
    return result


# --- validation --------------------------------------------------------------

def _validate_rule_payload(data, partial=False):
    """Return (values, error). `values` only contains provided fields."""
    values = {}
    if not partial or 'name' in data:
        name = (data.get('name') or '').strip()
        if not name:
            return None, 'Rule name is required'
        if len(name) > MAX_NAME_LEN:
            return None, f'Rule name must be at most {MAX_NAME_LEN} characters'
        values['name'] = name
    if 'scope' in data:
        scope = (data.get('scope') or 'ip').strip()
        if scope not in RATE_LIMIT_SCOPES:
            return None, f"scope must be one of {', '.join(RATE_LIMIT_SCOPES)}"
        values['scope'] = scope
    if not partial or 'limit_count' in data:
        try:
            limit_count = int(data.get('limit_count'))
        except (TypeError, ValueError):
            return None, 'limit_count must be an integer'
        if limit_count < 1 or limit_count > MAX_LIMIT:
            return None, f'limit_count must be between 1 and {MAX_LIMIT}'
        values['limit_count'] = limit_count
    if not partial or 'window_seconds' in data:
        try:
            window_seconds = int(data.get('window_seconds'))
        except (TypeError, ValueError):
            return None, 'window_seconds must be an integer'
        if window_seconds < 1 or window_seconds > MAX_WINDOW:
            return None, f'window_seconds must be between 1 and {MAX_WINDOW}'
        values['window_seconds'] = window_seconds
    if 'action' in data:
        action = (data.get('action') or 'monitor').strip()
        if action not in RATE_LIMIT_ACTIONS:
            return None, f"action must be one of {', '.join(RATE_LIMIT_ACTIONS)}"
        values['action'] = action
    if 'priority' in data:
        try:
            values['priority'] = int(data.get('priority'))
        except (TypeError, ValueError):
            return None, 'priority must be an integer'
    if 'is_enabled' in data:
        values['is_enabled'] = bool(data.get('is_enabled'))
    if 'site_id' in data:
        try:
            values['site_id'] = int(data.get('site_id'))
        except (TypeError, ValueError):
            return None, 'site_id must be an integer'
    return values, None


# --- rule endpoints ----------------------------------------------------------

@ratelimit_bp.route('/ratelimit/rules', methods=['GET'])
@token_required
def list_rules():
    query = RateLimitRule.query.filter_by(user_id=request.current_user.id)
    site_id = request.args.get('site_id', type=int)
    if site_id is not None:
        if not _get_owned_site(site_id, request.current_user):
            return jsonify({'error': 'Site not found'}), 404
        query = query.filter(RateLimitRule.site_id == site_id)

    rules = query.order_by(RateLimitRule.priority.desc(), RateLimitRule.id.asc()).all()
    return jsonify({'rules': [r.to_dict() for r in rules], 'total': len(rules)}), 200


@ratelimit_bp.route('/ratelimit/rules', methods=['POST'])
@token_required
def create_rule():
    data = request.get_json(silent=True) or {}
    values, error = _validate_rule_payload(data, partial=False)
    if error:
        return jsonify({'error': error}), 400

    site_id = values.get('site_id')
    if site_id is None:
        return jsonify({'error': 'site_id is required'}), 400
    site = _get_owned_site(site_id, request.current_user)
    if not site:
        return jsonify({'error': 'Site not found'}), 404

    rule = RateLimitRule(
        user_id=request.current_user.id,
        site_id=site.id,
        name=values['name'],
        scope=values.get('scope', 'ip'),
        limit_count=values['limit_count'],
        window_seconds=values['window_seconds'],
        # Never default to blocking; monitor is always the safe default.
        action=values.get('action', 'monitor'),
        priority=values.get('priority', 100),
        is_enabled=values.get('is_enabled', True),
    )
    try:
        db.session.add(rule)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create rate limit rule failed: {str(e)}")
        return jsonify({'error': 'Failed to create rule'}), 500

    logger.info(f"Rate limit rule created id={rule.id} site={site.id} by user={request.current_user.username}")
    return jsonify({'message': 'Rule created', 'rule': rule.to_dict()}), 201


@ratelimit_bp.route('/ratelimit/rules/<int:rule_id>', methods=['GET'])
@token_required
def get_rule(rule_id):
    rule = _get_owned_rule(rule_id, request.current_user)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    return jsonify({'rule': rule.to_dict()}), 200


@ratelimit_bp.route('/ratelimit/rules/<int:rule_id>', methods=['PATCH'])
@token_required
def update_rule(rule_id):
    rule = _get_owned_rule(rule_id, request.current_user)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404

    data = request.get_json(silent=True) or {}
    values, error = _validate_rule_payload(data, partial=True)
    if error:
        return jsonify({'error': error}), 400

    # A rule's site is immutable once created (avoids cross-site leaks).
    values.pop('site_id', None)
    for field, value in values.items():
        setattr(rule, field, value)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update rate limit rule failed: {str(e)}")
        return jsonify({'error': 'Failed to update rule'}), 500

    return jsonify({'message': 'Rule updated', 'rule': rule.to_dict()}), 200


@ratelimit_bp.route('/ratelimit/rules/<int:rule_id>', methods=['DELETE'])
@token_required
def delete_rule(rule_id):
    rule = _get_owned_rule(rule_id, request.current_user)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404

    try:
        db.session.delete(rule)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete rate limit rule failed: {str(e)}")
        return jsonify({'error': 'Failed to delete rule'}), 500

    logger.info(f"Rate limit rule deleted id={rule_id} by user={request.current_user.username}")
    return jsonify({'message': 'Rule deleted'}), 200


# --- check endpoint (dashboard + SDK) ----------------------------------------

@ratelimit_bp.route('/ratelimit/check', methods=['POST'])
def check_endpoint():
    """Count a request against a site's rate limit rules.

    Authenticable either by a dashboard bearer token (with `site_id` in the
    body) or by an SDK `X-API-Key` header (which determines the site). The
    client IP is resolved via the trusted-proxy configuration, never from a
    blindly-trusted header.
    """
    data = request.get_json(silent=True) or {}
    path = (data.get('path') or '').strip() or None
    ip = get_client_ip()

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
        site = _get_owned_site(site_id, user)
        if not site:
            return jsonify({'error': 'Site not found'}), 404
        user_id = user.id

    result = evaluate_rate_limit(site, api_key, ip, path=path, method=request.method, user_id=user_id)
    return jsonify({'result': result}), 200
