import os
import sys
import hashlib
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

from modules.database import (
    db, Site, ApiKey, Policy, PolicyRule, record_security_event,
    POLICY_MODES, RULE_MATCH_TYPES, RULE_ACTIONS,
)
from modules.auth import token_required, load_optional_user
from modules.events import get_client_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

policies_bp = Blueprint('policies', __name__, url_prefix='/api')

MAX_LABEL_LEN = 120
MAX_PATTERN_LEN = 500


# --- helpers -----------------------------------------------------------------

def _get_owned_site(site_id, user):
    """Fetch a site owned by `user`, or None (per-account isolation)."""
    return Site.query.filter_by(id=site_id, user_id=user.id).first()


def _get_owned_policy(policy_id, user):
    return Policy.query.filter_by(id=policy_id, user_id=user.id).first()


def _get_owned_rule(rule_id, user):
    return PolicyRule.query.filter_by(id=rule_id, user_id=user.id).first()


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


def _match_rule(rule, path):
    pattern = rule.path_pattern or ''
    if rule.match_type == 'exact':
        return path == pattern
    if rule.match_type == 'contains':
        return pattern in path
    # 'prefix' is the default.
    return path.startswith(pattern)


def _action_taken(decision, mode):
    """Enforced action given the detection verdict and the policy mode.

    In `monitor` mode a `block` verdict is never enforced: it is recorded as
    monitored. This keeps the detection verdict and the enforced action distinct.
    """
    if mode == 'monitor' and decision == 'block':
        return 'monitored'
    return {'allow': 'allowed', 'monitor': 'monitored', 'block': 'blocked'}[decision]


def evaluate_policy(site_id, path, method=None):
    """Evaluate the enabled policies of `site_id` against `path`.

    Rules are ordered by priority (higher first); the first enabled matching
    rule decides. When several policies match, the globally highest-priority
    rule wins. Returns a plain dict describing the outcome. Must be called
    inside an application context.
    """
    path = path or ''
    enabled_policies = Policy.query.filter_by(site_id=site_id, is_enabled=True).all()

    best_rule = None
    best_policy = None
    for policy in enabled_policies:
        for rule in sorted(policy.rules, key=lambda r: (-r.priority, r.id)):
            if not rule.is_enabled:
                continue
            if _match_rule(rule, path):
                if best_rule is None or rule.priority > best_rule.priority:
                    best_rule, best_policy = rule, policy
                break  # highest-priority match inside this policy

    if best_rule is None:
        return {
            'matched': False,
            'site_id': site_id,
            'policy_id': None,
            'policy_name': None,
            'policy_mode': None,
            'rule_id': None,
            'rule_label': None,
            'rule_action': None,
            'decision': 'allow',
            'action_taken': 'allowed',
            'effective': 'allow',
            'reason': 'no_matching_rule',
            'path': path,
        }

    decision = best_rule.action
    mode = best_policy.mode
    action_taken = _action_taken(decision, mode)
    if mode == 'monitor' and decision == 'block':
        reason = 'policy_monitor_mode'
    elif decision == 'allow':
        reason = 'rule_allow'
    elif decision == 'block':
        reason = 'rule_block'
    else:
        reason = 'rule_monitor'

    effective = {'allowed': 'allow', 'monitored': 'monitor', 'blocked': 'block'}[action_taken]
    return {
        'matched': True,
        'site_id': site_id,
        'policy_id': best_policy.id,
        'policy_name': best_policy.name,
        'policy_mode': mode,
        'rule_id': best_rule.id,
        'rule_label': best_rule.label,
        'rule_action': decision,
        'decision': decision,
        'action_taken': action_taken,
        'effective': effective,
        'reason': reason,
        'path': path,
    }


def _record_evaluation(site, user_id, ip, result):
    """Persist a security event for a matched policy decision (best-effort)."""
    try:
        record_security_event(
            current_app._get_current_object(),
            event_type='policy_evaluation',
            user_id=user_id,
            site_id=site.id,
            method=request.method,
            path=request.path,
            ip_address=ip,
            # Detection verdict vs. the action actually enforced.
            decision=result['decision'],
            action_taken=result['action_taken'],
            rule_id=str(result['rule_id']) if result['rule_id'] is not None else None,
            details={
                'reason': result['reason'],
                'evaluated_path': result['path'],
                'policy_id': result['policy_id'],
                'rule_label': result['rule_label'],
                'policy_mode': result['policy_mode'],
            },
        )
    except Exception:
        logger.exception('Failed to record policy evaluation event')


# --- validation --------------------------------------------------------------

def _validate_policy_payload(data, partial=False):
    """Return (values, error). `values` only contains provided fields."""
    values = {}
    if not partial or 'name' in data:
        name = (data.get('name') or '').strip()
        if not name:
            return None, 'Policy name is required'
        if len(name) > MAX_LABEL_LEN:
            return None, f'Policy name must be at most {MAX_LABEL_LEN} characters'
        values['name'] = name
    if 'mode' in data:
        mode = (data.get('mode') or 'monitor').strip()
        if mode not in POLICY_MODES:
            return None, f"mode must be one of {', '.join(POLICY_MODES)}"
        values['mode'] = mode
    if 'is_enabled' in data:
        values['is_enabled'] = bool(data.get('is_enabled'))
    if 'site_id' in data:
        try:
            values['site_id'] = int(data.get('site_id'))
        except (TypeError, ValueError):
            return None, 'site_id must be an integer'
    return values, None


def _validate_rule_payload(data, partial=False):
    values = {}
    if not partial or 'label' in data:
        label = (data.get('label') or '').strip()
        if not label:
            return None, 'Rule label is required'
        if len(label) > MAX_LABEL_LEN:
            return None, f'Rule label must be at most {MAX_LABEL_LEN} characters'
        values['label'] = label
    if not partial or 'path_pattern' in data:
        pattern = (data.get('path_pattern') or '').strip()
        if not pattern:
            return None, 'path_pattern is required'
        if len(pattern) > MAX_PATTERN_LEN:
            return None, f'path_pattern must be at most {MAX_PATTERN_LEN} characters'
        values['path_pattern'] = pattern
    if 'match_type' in data:
        match_type = (data.get('match_type') or 'prefix').strip()
        if match_type not in RULE_MATCH_TYPES:
            return None, f"match_type must be one of {', '.join(RULE_MATCH_TYPES)}"
        values['match_type'] = match_type
    if 'action' in data:
        action = (data.get('action') or 'monitor').strip()
        if action not in RULE_ACTIONS:
            return None, f"action must be one of {', '.join(RULE_ACTIONS)}"
        values['action'] = action
    if 'priority' in data:
        try:
            values['priority'] = int(data.get('priority'))
        except (TypeError, ValueError):
            return None, 'priority must be an integer'
    if 'is_enabled' in data:
        values['is_enabled'] = bool(data.get('is_enabled'))
    return values, None


# --- policy endpoints --------------------------------------------------------

@policies_bp.route('/policies', methods=['GET'])
@token_required
def list_policies():
    """List the account's policies, optionally narrowed to one site."""
    query = Policy.query.filter_by(user_id=request.current_user.id)
    site_id = request.args.get('site_id', type=int)
    if site_id is not None:
        # A caller may only narrow within their own account.
        if not _get_owned_site(site_id, request.current_user):
            return jsonify({'error': 'Site not found'}), 404
        query = query.filter(Policy.site_id == site_id)

    policies = query.order_by(Policy.created_at.desc()).all()
    return jsonify({
        'policies': [p.to_dict() for p in policies],
        'total': len(policies)
    }), 200


@policies_bp.route('/policies', methods=['POST'])
@token_required
def create_policy():
    data = request.get_json(silent=True) or {}
    values, error = _validate_policy_payload(data, partial=False)
    if error:
        return jsonify({'error': error}), 400

    site_id = values.get('site_id')
    if site_id is None:
        return jsonify({'error': 'site_id is required'}), 400
    site = _get_owned_site(site_id, request.current_user)
    if not site:
        return jsonify({'error': 'Site not found'}), 404

    policy = Policy(
        user_id=request.current_user.id,
        site_id=site.id,
        name=values['name'],
        # Never default to blocking; monitor mode is always the safe default.
        mode=values.get('mode', 'monitor'),
        is_enabled=values.get('is_enabled', True),
    )
    try:
        db.session.add(policy)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create policy failed: {str(e)}")
        return jsonify({'error': 'Failed to create policy'}), 500

    logger.info(f"Policy created id={policy.id} site={site.id} by user={request.current_user.username}")
    return jsonify({'message': 'Policy created', 'policy': policy.to_dict()}), 201


@policies_bp.route('/policies/<int:policy_id>', methods=['GET'])
@token_required
def get_policy(policy_id):
    policy = _get_owned_policy(policy_id, request.current_user)
    if not policy:
        return jsonify({'error': 'Policy not found'}), 404
    return jsonify({'policy': policy.to_dict()}), 200


@policies_bp.route('/policies/<int:policy_id>', methods=['PATCH'])
@token_required
def update_policy(policy_id):
    policy = _get_owned_policy(policy_id, request.current_user)
    if not policy:
        return jsonify({'error': 'Policy not found'}), 404

    data = request.get_json(silent=True) or {}
    values, error = _validate_policy_payload(data, partial=True)
    if error:
        return jsonify({'error': error}), 400

    # A policy's site is immutable once created (avoids cross-site leaks).
    values.pop('site_id', None)
    for field, value in values.items():
        setattr(policy, field, value)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update policy failed: {str(e)}")
        return jsonify({'error': 'Failed to update policy'}), 500

    return jsonify({'message': 'Policy updated', 'policy': policy.to_dict()}), 200


@policies_bp.route('/policies/<int:policy_id>', methods=['DELETE'])
@token_required
def delete_policy(policy_id):
    policy = _get_owned_policy(policy_id, request.current_user)
    if not policy:
        return jsonify({'error': 'Policy not found'}), 404

    try:
        db.session.delete(policy)  # cascades to this policy's rules
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete policy failed: {str(e)}")
        return jsonify({'error': 'Failed to delete policy'}), 500

    logger.info(f"Policy deleted id={policy_id} by user={request.current_user.username}")
    return jsonify({'message': 'Policy deleted'}), 200


# --- rule endpoints ----------------------------------------------------------

@policies_bp.route('/policies/<int:policy_id>/rules', methods=['POST'])
@token_required
def create_rule(policy_id):
    policy = _get_owned_policy(policy_id, request.current_user)
    if not policy:
        return jsonify({'error': 'Policy not found'}), 404

    data = request.get_json(silent=True) or {}
    values, error = _validate_rule_payload(data, partial=False)
    if error:
        return jsonify({'error': error}), 400

    rule = PolicyRule(
        policy_id=policy.id,
        user_id=request.current_user.id,
        label=values['label'],
        match_type=values.get('match_type', 'prefix'),
        path_pattern=values['path_pattern'],
        action=values.get('action', 'monitor'),
        priority=values.get('priority', 100),
        is_enabled=values.get('is_enabled', True),
    )
    try:
        db.session.add(rule)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create policy rule failed: {str(e)}")
        return jsonify({'error': 'Failed to create rule'}), 500

    return jsonify({'message': 'Rule created', 'rule': rule.to_dict()}), 201


@policies_bp.route('/policies/rules/<int:rule_id>', methods=['PATCH'])
@token_required
def update_rule(rule_id):
    rule = _get_owned_rule(rule_id, request.current_user)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404

    data = request.get_json(silent=True) or {}
    values, error = _validate_rule_payload(data, partial=True)
    if error:
        return jsonify({'error': error}), 400

    for field, value in values.items():
        setattr(rule, field, value)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update policy rule failed: {str(e)}")
        return jsonify({'error': 'Failed to update rule'}), 500

    return jsonify({'message': 'Rule updated', 'rule': rule.to_dict()}), 200


@policies_bp.route('/policies/rules/<int:rule_id>', methods=['DELETE'])
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
        logger.error(f"Delete policy rule failed: {str(e)}")
        return jsonify({'error': 'Failed to delete rule'}), 500

    return jsonify({'message': 'Rule deleted'}), 200


# --- evaluation endpoint (dashboard + SDK) -----------------------------------

@policies_bp.route('/policies/evaluate', methods=['POST'])
def evaluate_endpoint():
    """Evaluate a request path against a site's policies.

    Authenticable either by a dashboard bearer token (with `site_id` in the
    body) or by an SDK `X-API-Key` header (which determines the site). Only a
    matched rule is recorded as a security event, so unmatched requests do not
    flood the event log.
    """
    data = request.get_json(silent=True) or {}
    path = (data.get('path') or '').strip()
    if not path:
        return jsonify({'error': 'path is required'}), 400

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

    result = evaluate_policy(site.id, path, method=request.method)
    if result['matched']:
        _record_evaluation(site, user_id, ip, result)

    return jsonify({'result': result}), 200
