import os
import sys
import ipaddress
import datetime
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

from modules.database import db, SecurityEvent
from modules.auth import token_required, admin_required

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

events_bp = Blueprint('events', __name__, url_prefix='/api')

# Upper bound for a single page; keeps an unbounded `per_page` from exhausting
# memory on large event tables.
MAX_PER_PAGE = 200
DEFAULT_PER_PAGE = 50


def get_client_ip():
    """Return the best-known client IP for the current request.

    We never blindly trust `X-Forwarded-For`: the header is only consulted when
    the immediate peer (`request.remote_addr`) is a configured trusted proxy
    (`TRUSTED_PROXIES`). Otherwise `remote_addr` is authoritative. When trusted,
    the client address is the one `TRUSTED_PROXY_HOPS` positions from the right
    of the forwarded chain (the last entry is the closest proxy).
    """
    remote = request.remote_addr
    trusted = current_app.config.get('TRUSTED_PROXIES') or []
    if not trusted:
        return remote

    if not _is_trusted(remote, trusted):
        # The request did not arrive directly from a trusted proxy; ignore the
        # (spoofable) forwarded headers entirely.
        return remote

    forwarded = request.headers.get('X-Forwarded-For', '')
    chain = [part.strip() for part in forwarded.split(',') if part.strip()]
    if not chain:
        return remote

    hops = current_app.config.get('TRUSTED_PROXY_HOPS', 1) or 1
    # The trusted proxies append their own peer; walk `hops` back from the end.
    idx = len(chain) - hops
    if idx < 0:
        idx = 0
    candidate = chain[idx]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return remote
    return candidate


def _is_trusted(ip, trusted_list):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in trusted_list:
        try:
            if '/' in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _parse_dt(value, end_of_day=False):
    """Parse an ISO date or datetime from a query string. Returns None if invalid."""
    if not value:
        return None
    value = value.strip()
    try:
        dt = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is not None:
            dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        pass
    try:
        d = datetime.datetime.strptime(value, '%Y-%m-%d')
        if end_of_day:
            d = d + datetime.timedelta(days=1) - datetime.timedelta(microseconds=1)
        return d
    except ValueError:
        return None


@events_bp.route('/events', methods=['GET'])
@token_required
def list_events():
    """List security events for the current account with filters and pagination.

    Every event is scoped to the authenticated account; a `site_id` supplied by
    the caller can only narrow within that account (never across tenants).
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', DEFAULT_PER_PAGE, type=int)
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = DEFAULT_PER_PAGE
    per_page = min(per_page, MAX_PER_PAGE)

    query = SecurityEvent.query.filter_by(user_id=request.current_user.id)

    site_id = request.args.get('site_id', type=int)
    if site_id is not None:
        query = query.filter(SecurityEvent.site_id == site_id)

    event_type = request.args.get('event_type', '').strip()
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)

    threat_type = request.args.get('threat_type', '').strip()
    if threat_type:
        query = query.filter(SecurityEvent.threat_type == threat_type)

    decision = request.args.get('decision', '').strip()
    if decision:
        query = query.filter(SecurityEvent.decision == decision)

    action_taken = request.args.get('action_taken', '').strip()
    if action_taken:
        query = query.filter(SecurityEvent.action_taken == action_taken)

    ip_address = request.args.get('ip_address', '').strip()
    if ip_address:
        query = query.filter(SecurityEvent.ip_address == ip_address)

    path = request.args.get('path', '').strip()
    if path:
        query = query.filter(SecurityEvent.path.ilike(f'%{path}%'))

    date_from = _parse_dt(request.args.get('date_from'), end_of_day=False)
    if date_from:
        query = query.filter(SecurityEvent.created_at >= date_from)

    date_to = _parse_dt(request.args.get('date_to'), end_of_day=True)
    if date_to:
        query = query.filter(SecurityEvent.created_at <= date_to)

    pagination = query.order_by(SecurityEvent.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'events': [e.to_dict() for e in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'pages': pagination.pages
    }), 200


@events_bp.route('/events/<int:event_id>', methods=['GET'])
@token_required
def get_event(event_id):
    event = SecurityEvent.query.filter_by(
        id=event_id, user_id=request.current_user.id
    ).first()
    if not event:
        return jsonify({'error': 'Event not found'}), 404
    return jsonify({'event': event.to_dict()}), 200


def purge_old_events(app, retention_days=None):
    """Delete events older than the retention window. Returns count deleted.

    This is intentionally explicit-only: it is never scheduled automatically.
    `retention_days` falls back to the `EVENT_RETENTION_DAYS` config value.
    """
    if retention_days is None:
        retention_days = app.config.get('EVENT_RETENTION_DAYS', 90)
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
    try:
        with app.app_context():
            deleted = SecurityEvent.query.filter(SecurityEvent.created_at < cutoff).delete(
                synchronize_session=False
            )
            db.session.commit()
            logger.info(f"Purged {deleted} security events older than {retention_days} days")
            return deleted
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to purge security events: {str(e)}")
        return None


@events_bp.route('/events/purge', methods=['POST'])
@admin_required
def purge_events():
    """Explicitly purge events older than the retention window (admin only)."""
    data = request.get_json(silent=True) or {}
    days = data.get('retention_days')
    if days is not None:
        try:
            days = int(days)
            if days < 1:
                return jsonify({'error': 'retention_days must be a positive integer'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': 'retention_days must be an integer'}), 400

    deleted = purge_old_events(current_app._get_current_object(), days)
    if deleted is None:
        return jsonify({'error': 'Failed to purge events'}), 500

    effective_days = days if days is not None else current_app.config.get('EVENT_RETENTION_DAYS', 90)
    logger.info(f"Security event purge executed by admin={request.current_user.username} deleted={deleted}")
    return jsonify({
        'message': 'Purge completed',
        'deleted': deleted,
        'retention_days': effective_days
    }), 200
