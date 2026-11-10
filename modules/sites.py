import os
import sys
import hashlib
import secrets
import datetime
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app
from sqlalchemy.exc import IntegrityError

from modules.database import db, Site, ApiKey, Scan, Alert, record_security_event
from modules.auth import token_required
from modules.events import get_client_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

sites_bp = Blueprint('sites', __name__, url_prefix='/api')

# Public, non-secret prefix that makes keys recognisable in logs/config.
KEY_SCHEME = 'snt_'
# How many leading characters of the key we are allowed to display/store.
KEY_PREFIX_LENGTH = 12


def _pepper() -> str:
    return current_app.config.get('SENTINEL_API_KEY_PEPPER', '') or ''


def _hash_key(raw_key: str) -> str:
    """Return a deterministic SHA-256 hash of the secret key (+ server pepper)."""
    return hashlib.sha256((_pepper() + raw_key).encode('utf-8')).hexdigest()


def _generate_raw_key() -> str:
    """Create a new high-entropy key. The plaintext is never persisted."""
    return KEY_SCHEME + secrets.token_urlsafe(32)


def _make_key_pair():
    raw_key = _generate_raw_key()
    return raw_key, raw_key[:KEY_PREFIX_LENGTH], _hash_key(raw_key)


def _get_owned_site(site_id, user):
    """Fetch a site owned by `user`, or None. Enforces per-account isolation."""
    return Site.query.filter_by(id=site_id, user_id=user.id).first()


def _get_owned_key(key_id, user):
    return ApiKey.query.filter_by(id=key_id, user_id=user.id).first()


@sites_bp.route('/sites', methods=['POST'])
@token_required
def create_site():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    domain = (data.get('domain') or '').strip() or None

    if not name:
        return jsonify({'error': 'Site name is required'}), 400
    if len(name) > 120:
        return jsonify({'error': 'Site name must be at most 120 characters'}), 400
    if domain and len(domain) > 255:
        return jsonify({'error': 'Domain must be at most 255 characters'}), 400

    site = Site(user_id=request.current_user.id, name=name, domain=domain)
    try:
        db.session.add(site)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create site failed: {str(e)}")
        return jsonify({'error': 'Failed to create site'}), 500

    logger.info(f"Site created id={site.id} by user={request.current_user.username}")
    return jsonify({'message': 'Site created', 'site': site.to_dict()}), 201


@sites_bp.route('/sites', methods=['GET'])
@token_required
def list_sites():
    sites = Site.query.filter_by(user_id=request.current_user.id).order_by(Site.created_at.desc()).all()
    return jsonify({
        'sites': [s.to_dict() for s in sites],
        'total': len(sites)
    }), 200


@sites_bp.route('/sites/<int:site_id>', methods=['GET'])
@token_required
def get_site(site_id):
    site = _get_owned_site(site_id, request.current_user)
    if not site:
        return jsonify({'error': 'Site not found'}), 404
    return jsonify({'site': site.to_dict()}), 200


@sites_bp.route('/sites/<int:site_id>', methods=['PATCH'])
@token_required
def update_site(site_id):
    site = _get_owned_site(site_id, request.current_user)
    if not site:
        return jsonify({'error': 'Site not found'}), 404

    data = request.get_json(silent=True) or {}
    if 'name' in data:
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'error': 'Site name cannot be empty'}), 400
        if len(name) > 120:
            return jsonify({'error': 'Site name must be at most 120 characters'}), 400
        site.name = name
    if 'domain' in data:
        domain = (data.get('domain') or '').strip() or None
        if domain and len(domain) > 255:
            return jsonify({'error': 'Domain must be at most 255 characters'}), 400
        site.domain = domain
    if 'is_active' in data:
        site.is_active = bool(data.get('is_active'))

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update site failed: {str(e)}")
        return jsonify({'error': 'Failed to update site'}), 500

    return jsonify({'message': 'Site updated', 'site': site.to_dict()}), 200


@sites_bp.route('/sites/<int:site_id>', methods=['DELETE'])
@token_required
def delete_site(site_id):
    site = _get_owned_site(site_id, request.current_user)
    if not site:
        return jsonify({'error': 'Site not found'}), 404

    try:
        # Detach historical records first so the FK remains valid.
        Scan.query.filter_by(site_id=site.id).update({'site_id': None})
        Alert.query.filter_by(site_id=site.id).update({'site_id': None})
        db.session.delete(site)  # cascades to this site's api_keys
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete site failed: {str(e)}")
        return jsonify({'error': 'Failed to delete site'}), 500

    logger.info(f"Site deleted id={site_id} by user={request.current_user.username}")
    return jsonify({'message': 'Site deleted'}), 200


@sites_bp.route('/sites/<int:site_id>/keys', methods=['POST'])
@token_required
def create_key(site_id):
    site = _get_owned_site(site_id, request.current_user)
    if not site:
        return jsonify({'error': 'Site not found'}), 404

    data = request.get_json(silent=True) or {}
    name = (data.get('name') or 'default').strip() or 'default'
    if len(name) > 120:
        return jsonify({'error': 'Key name must be at most 120 characters'}), 400

    raw_key, key_prefix, key_hash = _make_key_pair()
    api_key = ApiKey(
        site_id=site.id,
        user_id=request.current_user.id,
        name=name,
        key_prefix=key_prefix,
        key_hash=key_hash
    )
    try:
        db.session.add(api_key)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Key generation collision, please retry'}), 500
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create API key failed: {str(e)}")
        return jsonify({'error': 'Failed to create API key'}), 500

    # Only the prefix is logged; the secret itself is never written to logs.
    logger.info(f"API key created id={api_key.id} prefix={key_prefix} site={site.id}")
    return jsonify({
        'message': 'API key created. Store it now; it will not be shown again.',
        'api_key': api_key.to_dict(),
        'key': raw_key
    }), 201


@sites_bp.route('/sites/<int:site_id>/keys', methods=['GET'])
@token_required
def list_keys(site_id):
    site = _get_owned_site(site_id, request.current_user)
    if not site:
        return jsonify({'error': 'Site not found'}), 404

    keys = ApiKey.query.filter_by(site_id=site.id).order_by(ApiKey.created_at.desc()).all()
    return jsonify({
        'keys': [k.to_dict() for k in keys],
        'total': len(keys)
    }), 200


@sites_bp.route('/keys/<int:key_id>/revoke', methods=['POST'])
@token_required
def revoke_key(key_id):
    api_key = _get_owned_key(key_id, request.current_user)
    if not api_key:
        return jsonify({'error': 'API key not found'}), 404

    if not api_key.is_active:
        return jsonify({'message': 'API key already revoked', 'api_key': api_key.to_dict()}), 200

    api_key.is_active = False
    api_key.revoked_at = datetime.datetime.utcnow()
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Revoke API key failed: {str(e)}")
        return jsonify({'error': 'Failed to revoke API key'}), 500

    logger.info(f"API key revoked id={api_key.id} prefix={api_key.key_prefix}")
    return jsonify({'message': 'API key revoked', 'api_key': api_key.to_dict()}), 200


@sites_bp.route('/keys/<int:key_id>/rotate', methods=['POST'])
@token_required
def rotate_key(key_id):
    old_key = _get_owned_key(key_id, request.current_user)
    if not old_key:
        return jsonify({'error': 'API key not found'}), 404

    site = _get_owned_site(old_key.site_id, request.current_user)
    if not site:
        return jsonify({'error': 'Site not found'}), 404

    raw_key, key_prefix, key_hash = _make_key_pair()
    new_key = ApiKey(
        site_id=site.id,
        user_id=request.current_user.id,
        name=old_key.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        rotated_from_id=old_key.id
    )
    try:
        old_key.is_active = False
        old_key.revoked_at = datetime.datetime.utcnow()
        db.session.add(new_key)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Key generation collision, please retry'}), 500
    except Exception as e:
        db.session.rollback()
        logger.error(f"Rotate API key failed: {str(e)}")
        return jsonify({'error': 'Failed to rotate API key'}), 500

    logger.info(f"API key rotated old={old_key.id} new={new_key.id} prefix={key_prefix}")
    return jsonify({
        'message': 'API key rotated. Store the new key now; it will not be shown again.',
        'api_key': new_key.to_dict(),
        'revoked_key_id': old_key.id,
        'key': raw_key
    }), 201


@sites_bp.route('/apikey-info', methods=['GET'])
def apikey_info():
    """Validate an API key supplied via the X-API-Key header.

    Intended for SDKs and agents to verify a key and discover the site it
    belongs to. The plaintext key is never echoed back. Each validation is
    recorded as a security event (attributable to the key's account/site).
    """
    raw_key = request.headers.get('X-API-Key')
    ip = get_client_ip()
    if not raw_key:
        logger.warning(f"apikey-info rejected: missing X-API-Key from {ip}")
        return jsonify({'error': 'X-API-Key header is missing'}), 401

    key_hash = _hash_key(raw_key)
    api_key = ApiKey.query.filter_by(key_hash=key_hash).first()
    if not api_key or not api_key.is_active:
        # Unattributable to an account, so it is only logged, not persisted.
        logger.warning(f"apikey-info rejected: invalid or revoked key from {ip}")
        return jsonify({'error': 'Invalid or revoked API key'}), 401

    site = Site.query.get(api_key.site_id)
    if not site or not site.is_active:
        _record_key_event(
            site, decision='deny', action_taken='rejected',
            threat_type='inactive_site', ip=ip,
            details={'reason': 'site_inactive', 'key_prefix': api_key.key_prefix}
        )
        return jsonify({'error': 'Site not found or inactive'}), 403

    try:
        api_key.last_used_at = datetime.datetime.utcnow()
        db.session.commit()
    except Exception:
        db.session.rollback()

    _record_key_event(
        site, decision='allow', action_taken='allowed',
        ip=ip, details={'key_prefix': api_key.key_prefix}
    )

    return jsonify({
        'valid': True,
        'api_key': {'id': api_key.id, 'name': api_key.name, 'key_prefix': api_key.key_prefix},
        'site': site.to_dict()
    }), 200


def _record_key_event(site, decision, action_taken=None, threat_type=None, ip=None, details=None):
    """Persist an API-key validation event for `site` (best-effort)."""
    try:
        record_security_event(
            current_app._get_current_object(),
            event_type='apikey_validation',
            user_id=getattr(site, 'user_id', None),
            site_id=getattr(site, 'id', None),
            threat_type=threat_type,
            method=request.method,
            path=request.path,
            ip_address=ip,
            decision=decision,
            action_taken=action_taken,
            details=details
        )
    except Exception:
        logger.exception('Failed to record API key validation event')
