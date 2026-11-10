import os
import sys
import hashlib
import ipaddress
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

from modules.database import (
    db, Site, ApiKey, AccessListRule, record_security_event,
    ACL_LIST_TYPES, ACL_MATCH_TYPES, ACL_MODES, ACL_SCOPES,
)
from modules.auth import token_required, load_optional_user
from modules.events import get_client_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

acl_bp = Blueprint('acl', __name__, url_prefix='/api')

MAX_VALUE_LEN = 500
MAX_DESC_LEN = 255


# --- helpers -----------------------------------------------------------------

def _get_owned_site(site_id, user):
    """Fetch a site owned by `user`, or None (per-account isolation)."""
    return Site.query.filter_by(id=site_id, user_id=user.id).first()


def _get_owned_rule(rule_id, user):
    return AccessListRule.query.filter_by(id=rule_id, user_id=user.id).first()


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


def _matches(rule, ip, path):
    """Whether an access-list rule matches the given request identity.

    `path` rules are prefix matches; `ip` rules compare a single address and
    `cidr` rules test membership in the network.
    """
    if rule.match_type == 'path':
        return bool(path) and path.startswith(rule.value)
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    try:
        if rule.match_type == 'ip':
            return addr == ipaddress.ip_address(rule.value)
        if rule.match_type == 'cidr':
            return addr in ipaddress.ip_network(rule.value, strict=False)
    except ValueError:
        return False
    return False


def evaluate_access_list(site_id, ip=None, path=None):
    """Evaluate a site's active access-list rules against a request identity.

    Precedence is explicit and documented:
      1. Explicit deny (`block`) rules always take precedence over allow rules.
      2. Within the same `list_type`, the higher `priority` is evaluated first.
      3. An `allow` match returns only the protection scopes it explicitly
         exempts (`bypass_scopes`); an empty `scope` exempts nothing, so an
         allow rule never bypasses all protections by default.

    A `block` rule in 'monitor' mode yields decision 'block' but action
    'monitored' (detection verdict vs. enforced action stay distinct). Returns
    a plain dict; must run inside an application context.
    """
    rules = AccessListRule.query.filter_by(site_id=site_id, is_active=True).order_by(
        AccessListRule.priority.desc(), AccessListRule.id.asc()
    ).all()

    # 1) deny wins — evaluate block rules first, highest priority first.
    for rule in rules:
        if rule.list_type != 'block':
            continue
        if _matches(rule, ip, path):
            enforced = rule.mode == 'block'
            return {
                'matched': True,
                'site_id': site_id,
                'list_type': 'block',
                'rule_id': rule.id,
                'match_type': rule.match_type,
                'value': rule.value,
                'mode': rule.mode,
                'bypass_scopes': [],
                'decision': 'block',
                'action_taken': 'blocked' if enforced else 'monitored',
                'enforced': enforced,
                'reason': 'block_rule' if enforced else 'block_rule_monitor',
            }

    # 2) allow rules — only exempt the scopes they explicitly list.
    for rule in rules:
        if rule.list_type != 'allow':
            continue
        if _matches(rule, ip, path):
            bypass = rule.scope_list()
            return {
                'matched': True,
                'site_id': site_id,
                'list_type': 'allow',
                'rule_id': rule.id,
                'match_type': rule.match_type,
                'value': rule.value,
                'mode': rule.mode,
                'bypass_scopes': bypass,
                'decision': 'allow',
                'action_taken': 'allowed',
                'enforced': False,
                'reason': 'allow_rule',
            }

    return {
        'matched': False,
        'site_id': site_id,
        'list_type': None,
        'rule_id': None,
        'match_type': None,
        'value': None,
        'mode': None,
        'bypass_scopes': [],
        'decision': 'allow',
        'action_taken': 'allowed',
        'enforced': False,
        'reason': 'no_matching_rule',
    }


def _record_block_event(site, user_id, ip, path, result):
    """Persist a security event when a block rule matches (best-effort)."""
    try:
        record_security_event(
            current_app._get_current_object(),
            event_type='acl_block',
            threat_type='access_list_block',
            user_id=user_id,
            site_id=site.id,
            method=request.method,
            path=path or request.path,
            ip_address=ip,
            decision=result['decision'],
            action_taken=result['action_taken'],
            rule_id=str(result['rule_id']) if result['rule_id'] is not None else None,
            details={
                'reason': result['reason'],
                'match_type': result['match_type'],
                'mode': result['mode'],
            },
        )
    except Exception:
        logger.exception('Failed to record access list block event')


def _record_acl_change(site, user, action, rule, before=None):
    """Audit a change to the access list: who changed what (best-effort)."""
    try:
        record_security_event(
            current_app._get_current_object(),
            event_type='acl_changed',
            user_id=user.id if user else None,
            site_id=site.id,
            method=request.method,
            path=request.path,
            ip_address=get_client_ip(),
            decision=action,
            action_taken='recorded',
            rule_id=str(rule.id) if rule and rule.id is not None else None,
            details={
                'action': action,
                'actor_id': user.id if user else None,
                'actor_username': user.username if user else None,
                'rule': rule.to_dict() if rule else None,
                'before': before,
            },
        )
    except Exception:
        logger.exception('Failed to record access list change')


# --- validation --------------------------------------------------------------

def _validate_acl_payload(data, partial=False):
    """Return (values, error). `values` only contains provided fields."""
    values = {}

    if not partial or 'list_type' in data:
        list_type = (data.get('list_type') or '').strip()
        if list_type not in ACL_LIST_TYPES:
            return None, f"list_type must be one of {', '.join(ACL_LIST_TYPES)}"
        values['list_type'] = list_type

    if not partial or 'match_type' in data:
        match_type = (data.get('match_type') or '').strip()
        if match_type not in ACL_MATCH_TYPES:
            return None, f"match_type must be one of {', '.join(ACL_MATCH_TYPES)}"
        values['match_type'] = match_type

    if not partial or 'value' in data:
        value = (data.get('value') or '').strip()
        if not value:
            return None, 'value is required'
        if len(value) > MAX_VALUE_LEN:
            return None, f'value must be at most {MAX_VALUE_LEN} characters'
        # Validate against the (possibly just-provided) match type.
        match_type = values.get('match_type', (data.get('match_type') or '').strip())
        if match_type in ('ip', 'cidr'):
            try:
                if match_type == 'ip':
                    ipaddress.ip_address(value)
                else:
                    ipaddress.ip_network(value, strict=False)
            except ValueError:
                return None, f'value is not a valid {match_type}'
        values['value'] = value

    if 'scope' in data:
        raw_scope = data.get('scope')
        if isinstance(raw_scope, str):
            scopes = [s.strip() for s in raw_scope.split(',') if s.strip()]
        elif isinstance(raw_scope, (list, tuple)):
            scopes = [str(s).strip() for s in raw_scope if str(s).strip()]
        else:
            return None, 'scope must be a string or a list'
        invalid = [s for s in scopes if s not in ACL_SCOPES]
        if invalid:
            return None, f"scope entries must be among {', '.join(ACL_SCOPES)}"
        values['scope'] = ','.join(dict.fromkeys(scopes))  # de-dup, keep order

    if 'mode' in data:
        mode = (data.get('mode') or 'monitor').strip()
        if mode not in ACL_MODES:
            return None, f"mode must be one of {', '.join(ACL_MODES)}"
        values['mode'] = mode

    if 'priority' in data:
        try:
            values['priority'] = int(data.get('priority'))
        except (TypeError, ValueError):
            return None, 'priority must be an integer'

    if 'description' in data:
        description = (data.get('description') or '').strip() or None
        if description and len(description) > MAX_DESC_LEN:
            return None, f'description must be at most {MAX_DESC_LEN} characters'
        values['description'] = description

    if 'is_active' in data:
        values['is_active'] = bool(data.get('is_active'))

    if 'site_id' in data:
        try:
            values['site_id'] = int(data.get('site_id'))
        except (TypeError, ValueError):
            return None, 'site_id must be an integer'

    return values, None


# --- rule endpoints ----------------------------------------------------------

@acl_bp.route('/acl/rules', methods=['GET'])
@token_required
def list_rules():
    query = AccessListRule.query.filter_by(user_id=request.current_user.id)
    site_id = request.args.get('site_id', type=int)
    if site_id is not None:
        if not _get_owned_site(site_id, request.current_user):
            return jsonify({'error': 'Site not found'}), 404
        query = query.filter(AccessListRule.site_id == site_id)
    list_type = request.args.get('list_type')
    if list_type is not None:
        if list_type not in ACL_LIST_TYPES:
            return jsonify({'error': f"list_type must be one of {', '.join(ACL_LIST_TYPES)}"}), 400
        query = query.filter(AccessListRule.list_type == list_type)

    rules = query.order_by(
        AccessListRule.priority.desc(), AccessListRule.id.asc()
    ).all()
    return jsonify({'rules': [r.to_dict() for r in rules], 'total': len(rules)}), 200


@acl_bp.route('/acl/rules', methods=['POST'])
@token_required
def create_rule():
    data = request.get_json(silent=True) or {}
    values, error = _validate_acl_payload(data, partial=False)
    if error:
        return jsonify({'error': error}), 400

    site_id = values.get('site_id')
    if site_id is None:
        return jsonify({'error': 'site_id is required'}), 400
    site = _get_owned_site(site_id, request.current_user)
    if not site:
        return jsonify({'error': 'Site not found'}), 404

    rule = AccessListRule(
        user_id=request.current_user.id,
        site_id=site.id,
        list_type=values['list_type'],
        match_type=values['match_type'],
        value=values['value'],
        scope=values.get('scope', ''),
        # Never default to blocking; monitor is always the safe default.
        mode=values.get('mode', 'monitor'),
        priority=values.get('priority', 100),
        description=values.get('description'),
        is_active=values.get('is_active', True),
        created_by_user_id=request.current_user.id,
    )
    try:
        db.session.add(rule)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create access list rule failed: {str(e)}")
        return jsonify({'error': 'Failed to create rule'}), 500

    logger.info(f"Access list rule created id={rule.id} site={site.id} by user={request.current_user.username}")
    _record_acl_change(site, request.current_user, 'create', rule)
    return jsonify({'message': 'Rule created', 'rule': rule.to_dict()}), 201


@acl_bp.route('/acl/rules/<int:rule_id>', methods=['GET'])
@token_required
def get_rule(rule_id):
    rule = _get_owned_rule(rule_id, request.current_user)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    return jsonify({'rule': rule.to_dict()}), 200


@acl_bp.route('/acl/rules/<int:rule_id>', methods=['PATCH'])
@token_required
def update_rule(rule_id):
    rule = _get_owned_rule(rule_id, request.current_user)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404

    data = request.get_json(silent=True) or {}
    values, error = _validate_acl_payload(data, partial=True)
    if error:
        return jsonify({'error': error}), 400

    # A rule's site is immutable once created (avoids cross-site leaks).
    values.pop('site_id', None)
    before = rule.to_dict()
    for field, value in values.items():
        setattr(rule, field, value)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update access list rule failed: {str(e)}")
        return jsonify({'error': 'Failed to update rule'}), 500

    site = Site.query.get(rule.site_id)
    _record_acl_change(site, request.current_user, 'update', rule, before=before)
    return jsonify({'message': 'Rule updated', 'rule': rule.to_dict()}), 200


@acl_bp.route('/acl/rules/<int:rule_id>', methods=['DELETE'])
@token_required
def delete_rule(rule_id):
    rule = _get_owned_rule(rule_id, request.current_user)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404

    site = Site.query.get(rule.site_id)
    snapshot = rule.to_dict()
    try:
        db.session.delete(rule)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete access list rule failed: {str(e)}")
        return jsonify({'error': 'Failed to delete rule'}), 500

    logger.info(f"Access list rule deleted id={rule_id} by user={request.current_user.username}")
    # The row is gone; the audit entry keeps a snapshot of what was removed.
    _record_acl_change(site, request.current_user, 'delete', None, before=snapshot)
    return jsonify({'message': 'Rule deleted'}), 200


# --- check endpoint (dashboard + SDK) ----------------------------------------

@acl_bp.route('/acl/check', methods=['POST'])
def check_endpoint():
    """Evaluate a request against a site's access lists.

    Authenticable either by a dashboard bearer token (with `site_id` in the
    body) or by an SDK `X-API-Key` header (which determines the site). The
    client IP is resolved via the trusted-proxy configuration, never from a
    blindly-trusted header. A matching block rule is recorded as a security
    event; allow/neutral results are not (to avoid log flooding).
    """
    data = request.get_json(silent=True) or {}
    path = (data.get('path') or '').strip() or None
    ip = (data.get('ip') or '').strip() or get_client_ip()

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

    result = evaluate_access_list(site.id, ip=ip, path=path)
    if result['matched'] and result['list_type'] == 'block':
        _record_block_event(site, user_id, ip, path, result)

    return jsonify({'result': result}), 200
