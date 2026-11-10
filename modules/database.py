import os
import sys
import logging
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

# NOTE on PostgreSQL compatibility (no schema changes made):
# All models below use `db.Model` as their base (correct for Flask-SQLAlchemy)
# and only column types that map identically across SQLite and PostgreSQL:
# Integer, String, Float, DateTime, Text, Boolean, ForeignKey. None of the
# tables use a native JSON or ENUM column type — `details` (Scan) and
# `alert_metadata` (Alert) store JSON as serialized text via json.dumps/
# json.loads in Python, which is dialect-agnostic and requires no change to
# run against PostgreSQL. If a native JSON column is introduced later, use
# `from sqlalchemy.dialects.postgresql import JSONB` for it; that would be a
# schema change and is intentionally not applied here.
db = SQLAlchemy()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class User(db.Model):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(80), nullable=True)
    last_name = Column(String(80), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    scans = relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')
    alerts = relationship('Alert', backref='user', lazy=True, cascade='all, delete-orphan')
    sites = relationship('Site', backref='owner', lazy=True, cascade='all, delete-orphan')
    notification_channels = relationship('NotificationChannel', backref='owner', lazy=True, cascade='all, delete-orphan')
    policies = relationship('Policy', backref='owner', lazy=True, cascade='all, delete-orphan')
    rate_limits = relationship('RateLimitRule', backref='owner', lazy=True, cascade='all, delete-orphan')
    access_lists = relationship(
        'AccessListRule', backref='owner', lazy=True,
        cascade='all, delete-orphan', foreign_keys='AccessListRule.user_id'
    )
    password_resets = relationship(
        'PasswordResetToken', backref='user', lazy=True, cascade='all, delete-orphan'
    )

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    def __repr__(self):
        return f'<User {self.username}>'


class Scan(db.Model):
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=True, index=True)
    module = Column(String(50), nullable=False, index=True)
    target = Column(String(500), nullable=True)
    risk_score = Column(Float, default=0.0, nullable=False)
    status = Column(String(20), default='completed', nullable=False)
    details = Column(Text, nullable=True)
    raw_input_size = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self):
        import json
        try:
            parsed_details = json.loads(self.details) if self.details else None
        except (json.JSONDecodeError, TypeError):
            parsed_details = self.details
        return {
            'id': self.id,
            'user_id': self.user_id,
            'module': self.module,
            'target': self.target,
            'risk_score': self.risk_score,
            'status': self.status,
            'details': parsed_details,
            'raw_input_size': self.raw_input_size,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<Scan {self.id} module={self.module} risk={self.risk_score}>'


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=True, index=True)
    source = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default='info')
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=True)
    is_read = Column(Boolean, default=False, nullable=False)
    alert_metadata = Column('alert_metadata', Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self):
        import json
        try:
            parsed_meta = json.loads(self.alert_metadata) if self.alert_metadata else None
        except (json.JSONDecodeError, TypeError):
            parsed_meta = self.alert_metadata
        return {
            'id': self.id,
            'user_id': self.user_id,
            'site_id': self.site_id,
            'source': self.source,
            'severity': self.severity,
            'title': self.title,
            'message': self.message,
            'is_read': self.is_read,
            'metadata': parsed_meta,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<Alert {self.id} source={self.source} severity={self.severity}>'


class Site(db.Model):
    """A monitored website/application owned by exactly one account."""
    __tablename__ = 'sites'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    domain = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    api_keys = relationship('ApiKey', backref='site', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'domain': self.domain,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<Site {self.id} name={self.name}>'


class ApiKey(db.Model):
    """API key for a site.

    Only a SHA-256 hash of the secret is persisted; the plaintext value is
    returned exactly once, at creation time, and is never stored or logged.
    """
    __tablename__ = 'api_keys'

    id = Column(Integer, primary_key=True, autoincrement=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    key_prefix = Column(String(16), nullable=False, index=True)
    key_hash = Column(String(128), nullable=False, unique=True, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    rotated_from_id = Column(Integer, ForeignKey('api_keys.id'), nullable=True)

    def to_dict(self):
        # Never expose key_hash in API responses.
        return {
            'id': self.id,
            'site_id': self.site_id,
            'user_id': self.user_id,
            'name': self.name,
            'key_prefix': self.key_prefix,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'rotated_from_id': self.rotated_from_id
        }

    def __repr__(self):
        return f'<ApiKey {self.id} site={self.site_id} prefix={self.key_prefix}>'


class SecurityEvent(db.Model):
    """A single audit/security event recorded by the detection pipeline.

    This is an append-only event log. It deliberately separates the *detection
    decision* (`decision`, the verdict produced by the detection layer) from the
    *enforced action* (`action_taken`, what the system actually did — e.g.
    `monitored` while in observation mode vs. `blocked`). No sensitive request
    content (passwords, tokens, headers, bodies) is stored: callers must pass
    already-sanitized data through `record_security_event`.
    """
    __tablename__ = 'security_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    threat_type = Column(String(80), nullable=True, index=True)
    method = Column(String(10), nullable=True)
    path = Column(String(500), nullable=True)
    ip_address = Column(String(64), nullable=True, index=True)
    # `decision` = the detection verdict (e.g. allow / challenge / block / suspicious)
    decision = Column(String(20), nullable=True, index=True)
    # `action_taken` = what was actually enforced (e.g. monitored / blocked / allowed)
    action_taken = Column(String(20), nullable=True, index=True)
    confidence = Column(Float, nullable=True)
    rule_id = Column(String(120), nullable=True, index=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self):
        import json
        try:
            parsed_details = json.loads(self.details) if self.details else None
        except (json.JSONDecodeError, TypeError):
            parsed_details = self.details
        return {
            'id': self.id,
            'user_id': self.user_id,
            'site_id': self.site_id,
            'event_type': self.event_type,
            'threat_type': self.threat_type,
            'method': self.method,
            'path': self.path,
            'ip_address': self.ip_address,
            'decision': self.decision,
            'action_taken': self.action_taken,
            'confidence': self.confidence,
            'rule_id': self.rule_id,
            'details': parsed_details,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<SecurityEvent {self.id} type={self.event_type} decision={self.decision}>'


# --- Notification channels ---------------------------------------------------
# Field names inside a channel's `config` that hold secrets. These values are
# stored server-side only and are never returned to the browser.
_CHANNEL_SECRET_FIELDS = {
    'email': {'smtp_password'},
    'slack': {'webhook_url'},
    'telegram': {'bot_token'},
    'whatsapp': {'access_token'},
}
_CHANNEL_PUBLIC_FIELDS = {
    'email': {'to_address', 'smtp_host', 'smtp_port', 'smtp_user', 'use_tls'},
    'slack': {'channel_label'},
    'telegram': {'chat_id'},
    'whatsapp': {'phone_number_id', 'to_number'},
}


class NotificationChannel(db.Model):
    """A notification channel configured by an account (optionally per site).

    Secrets (SMTP password, webhook URL, bot token, access token) live in the
    `config` JSON column on the server and are NEVER returned by the API. A
    channel is only considered usable once `is_verified` is True, which is set
    after a successful real test send — never proactively.
    """
    __tablename__ = 'notification_channels'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=True, index=True)
    channel_type = Column(String(20), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    config = Column(Text, nullable=True)
    min_severity = Column(String(10), default='medium', nullable=False)
    is_enabled = Column(Boolean, default=False, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    last_tested_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def _parsed_config(self):
        import json
        try:
            return json.loads(self.config) if self.config else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    def to_public_dict(self):
        """Serialize without exposing any secret value.

        Secret fields are omitted entirely; a `has_secret` map indicates which
        of them are set so the UI can render "configured" state.
        """
        cfg = self._parsed_config()
        secret_fields = _CHANNEL_SECRET_FIELDS.get(self.channel_type, set())
        public_fields = _CHANNEL_PUBLIC_FIELDS.get(self.channel_type, set())
        public_config = {k: cfg.get(k) for k in public_fields if k in cfg}
        has_secret = {f: bool(cfg.get(f)) for f in secret_fields}
        return {
            'id': self.id,
            'user_id': self.user_id,
            'site_id': self.site_id,
            'channel_type': self.channel_type,
            'name': self.name,
            'config': public_config,
            'has_secret': has_secret,
            'min_severity': self.min_severity,
            'is_enabled': self.is_enabled,
            'is_verified': self.is_verified,
            'last_tested_at': self.last_tested_at.isoformat() if self.last_tested_at else None,
            'last_error': self.last_error,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f'<NotificationChannel {self.id} type={self.channel_type}>'


class NotificationLog(db.Model):
    """Delivery/audit trail for notifications (per channel attempt)."""
    __tablename__ = 'notification_log'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=True, index=True)
    channel_id = Column(Integer, ForeignKey('notification_channels.id'), nullable=True, index=True)
    event_id = Column(Integer, ForeignKey('security_events.id'), nullable=True, index=True)
    channel_type = Column(String(20), nullable=True)
    # status: sent | failed | skipped | aggregated | test
    status = Column(String(20), nullable=False, index=True)
    subject = Column(String(200), nullable=True)
    detail = Column(Text, nullable=True)
    dedup_key = Column(String(200), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'site_id': self.site_id,
            'channel_id': self.channel_id,
            'event_id': self.event_id,
            'channel_type': self.channel_type,
            'status': self.status,
            'subject': self.subject,
            'detail': self.detail,
            'dedup_key': self.dedup_key,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<NotificationLog {self.id} status={self.status}>'


class NotificationAggregate(db.Model):
    """Aggregation ledger used to collapse repeated events within a window.

    Keeps a running count per (channel_id, dedup_key) so bursts of identical
    events produce a single notification plus a suppressed count.
    """
    __tablename__ = 'notification_aggregates'

    id = Column(Integer, primary_key=True, autoincrement=True)
    channel_id = Column(Integer, ForeignKey('notification_channels.id'), nullable=False, index=True)
    dedup_key = Column(String(200), nullable=False, index=True)
    window_start = Column(DateTime, default=datetime.utcnow, nullable=False)
    count = Column(Integer, default=0, nullable=False)
    last_event_id = Column(Integer, ForeignKey('security_events.id'), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<NotificationAggregate ch={self.channel_id} count={self.count}>'


# --- Policies ----------------------------------------------------------------
# A Policy is scoped to exactly one site and runs in one of two modes:
#   'monitor' -> observations only; no rule can cause an enforced block.
#   'block'   -> a matching rule with action 'block' may actually block.
# New policies always default to 'monitor'; blocking is never enabled implicitly.
POLICY_MODES = ('monitor', 'block')
RULE_MATCH_TYPES = ('prefix', 'exact', 'contains')
RULE_ACTIONS = ('allow', 'monitor', 'block')


class Policy(db.Model):
    """An independent set of path rules for a single site."""
    __tablename__ = 'policies'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    mode = Column(String(20), default='monitor', nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    rules = relationship(
        'PolicyRule', backref='policy', lazy=True,
        cascade='all, delete-orphan', order_by='PolicyRule.priority.desc()'
    )

    def to_dict(self, include_rules=True):
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'site_id': self.site_id,
            'name': self.name,
            'mode': self.mode,
            'is_enabled': self.is_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_rules:
            data['rules'] = [r.to_dict() for r in self.rules]
        return data

    def __repr__(self):
        return f'<Policy {self.id} site={self.site_id} mode={self.mode}>'


class PolicyRule(db.Model):
    """A single path-matching rule inside a policy, evaluated by priority."""
    __tablename__ = 'policy_rules'

    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_id = Column(Integer, ForeignKey('policies.id'), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    label = Column(String(120), nullable=False)
    match_type = Column(String(20), default='prefix', nullable=False)
    path_pattern = Column(String(500), nullable=False)
    # Recommended action when this rule matches (subject to the policy mode).
    action = Column(String(20), default='monitor', nullable=False)
    # Higher priority is evaluated first.
    priority = Column(Integer, default=100, nullable=False, index=True)
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'policy_id': self.policy_id,
            'user_id': self.user_id,
            'label': self.label,
            'match_type': self.match_type,
            'path_pattern': self.path_pattern,
            'action': self.action,
            'priority': self.priority,
            'is_enabled': self.is_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f'<PolicyRule {self.id} {self.match_type}:{self.path_pattern} action={self.action}>'


# --- Rate limiting -----------------------------------------------------------
# A RateLimitRule is scoped to exactly one site and counts requests for one
# identity dimension: the client IP ('ip') or the calling API key ('api_key').
# A fixed window (`window_seconds`) is used; the default action is 'monitor' so
# exceeding a limit is only observed unless the rule explicitly blocks.
RATE_LIMIT_SCOPES = ('ip', 'api_key')
RATE_LIMIT_ACTIONS = ('monitor', 'block')


class RateLimitRule(db.Model):
    """A per-site request cap for one identity dimension (IP or API key)."""
    __tablename__ = 'rate_limit_rules'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    # Which identity the counter is keyed on.
    scope = Column(String(10), default='ip', nullable=False)
    # Allow at most `limit_count` requests per `window_seconds`.
    limit_count = Column(Integer, default=60, nullable=False)
    window_seconds = Column(Integer, default=60, nullable=False)
    # 'monitor' observes over-limit requests; 'block' is enforced by the caller.
    action = Column(String(20), default='monitor', nullable=False)
    # Higher priority wins when several rules share a scope.
    priority = Column(Integer, default=100, nullable=False, index=True)
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'site_id': self.site_id,
            'name': self.name,
            'scope': self.scope,
            'limit_count': self.limit_count,
            'window_seconds': self.window_seconds,
            'action': self.action,
            'priority': self.priority,
            'is_enabled': self.is_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f'<RateLimitRule {self.id} site={self.site_id} scope={self.scope} {self.limit_count}/{self.window_seconds}s>'


class RateLimitCounter(db.Model):
    """A fixed-window counter row, shared across app instances via the database.

    Only a one-way hash of the identity is stored (`key_hash`), never the raw
    IP or API key. A unique constraint over the window key makes the atomic
    increment safe when several instances write concurrently.
    """
    __tablename__ = 'rate_limit_counters'
    __table_args__ = (
        UniqueConstraint('site_id', 'scope', 'key_hash', 'window_start',
                         name='uq_rate_limit_counter'),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=False, index=True)
    scope = Column(String(10), nullable=False)
    key_hash = Column(String(64), nullable=False, index=True)
    window_start = Column(DateTime, nullable=False, index=True)
    count = Column(Integer, default=0, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<RateLimitCounter site={self.site_id} scope={self.scope} count={self.count}>'


# --- Access lists (allow / block) --------------------------------------------
# An AccessListRule is scoped to exactly one site and matches either a client
# IP / CIDR range or a request path prefix. Explicit deny (`block`) rules always
# take precedence over `allow` rules; within the same list_type the higher
# priority is evaluated first. An `allow` rule only exempts the protection
# scopes listed in `scope` (never all protections by default: an empty `scope`
# exempts nothing). Blocking is never enabled implicitly — `mode` defaults to
# 'monitor', which records the match without enforcing it.
ACL_LIST_TYPES = ('allow', 'block')
ACL_MATCH_TYPES = ('ip', 'cidr', 'path')
ACL_MODES = ('monitor', 'block')
# Protection scopes an `allow` rule may exempt (explicit opt-in only).
ACL_SCOPES = ('policies', 'ratelimit', 'botguard')


class AccessListRule(db.Model):
    """A per-site allow/deny entry for an IP, CIDR range or path prefix."""
    __tablename__ = 'access_list_rules'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    site_id = Column(Integer, ForeignKey('sites.id'), nullable=False, index=True)
    # 'allow' | 'block'
    list_type = Column(String(10), nullable=False, index=True)
    # 'ip' | 'cidr' | 'path'
    match_type = Column(String(10), nullable=False)
    value = Column(String(500), nullable=False)
    # Comma-separated subset of ACL_SCOPES that an `allow` rule exempts. Empty
    # means the allow rule exempts no protection at all.
    scope = Column(String(120), default='', nullable=False)
    # 'monitor' records the match; 'block' is enforced by the caller.
    mode = Column(String(10), default='monitor', nullable=False)
    # Higher priority is evaluated first within the same list_type.
    priority = Column(Integer, default=100, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def scope_list(self):
        return [s.strip() for s in (self.scope or '').split(',') if s.strip()]

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'site_id': self.site_id,
            'list_type': self.list_type,
            'match_type': self.match_type,
            'value': self.value,
            'scope': self.scope_list(),
            'mode': self.mode,
            'priority': self.priority,
            'description': self.description,
            'is_active': self.is_active,
            'created_by_user_id': self.created_by_user_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f'<AccessListRule {self.id} site={self.site_id} {self.list_type}:{self.match_type}={self.value}>'


class PasswordResetToken(db.Model):
    """A single-use, expiring password-reset token.

    Only the SHA-256 hash of the token is stored; the raw token is delivered to
    the user once and never persisted, logged or returned by any API. The token
    is valid until `expires_at` and can be consumed only once (`used_at`). A
    plain SHA-256 (no pepper) is sufficient here because the raw token is 256
    bits of CSPRNG output, so brute-forcing the hash is infeasible.
    """
    __tablename__ = 'password_reset_tokens'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime, nullable=True)
    requested_ip = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def is_valid(self, at=None):
        at = at or datetime.utcnow()
        return self.used_at is None and self.expires_at is not None and self.expires_at >= at

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'used_at': self.used_at.isoformat() if self.used_at else None,
            'requested_ip': self.requested_ip,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<PasswordResetToken user={self.user_id} used={self.used_at is not None}>'


def init_db(app):
    try:
        with app.app_context():
            db.create_all()
            logger.info("Database tables initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise


def save_scan_record(app, user_id, module, target, risk_score, details, raw_input_size=None, status='completed'):
    import json
    try:
        with app.app_context():
            scan = Scan(
                user_id=user_id,
                module=module,
                target=target,
                risk_score=risk_score,
                status=status,
                details=json.dumps(details) if isinstance(details, (dict, list)) else str(details),
                raw_input_size=raw_input_size
            )
            db.session.add(scan)
            db.session.commit()
            return scan.id
    except Exception as e:
        logger.error(f"Failed to save scan record: {str(e)}")
        db.session.rollback()
        return None


def save_alert_record(app, user_id, source, severity, title, message, alert_metadata=None, site_id=None):
    import json
    try:
        with app.app_context():
            alert = Alert(
                user_id=user_id,
                site_id=site_id,
                source=source,
                severity=severity,
                title=title,
                message=message,
                alert_metadata=json.dumps(alert_metadata) if isinstance(alert_metadata, (dict, list)) else str(alert_metadata) if alert_metadata else None
            )
            db.session.add(alert)
            db.session.commit()
            return alert.id
    except Exception as e:
        logger.error(f"Failed to save alert record: {str(e)}")
        db.session.rollback()
        return None


# Keys whose values must never be persisted in an event's `details` payload.
_SENSITIVE_DETAIL_KEYS = {
    'password', 'passwd', 'pwd', 'secret', 'token', 'access_token',
    'refresh_token', 'authorization', 'auth', 'api_key', 'apikey',
    'key', 'cookie', 'set-cookie', 'session', 'session_id', 'csrf',
    'card', 'card_number', 'cvv', 'cvc', 'ssn', 'pin'
}
_REDACTED = '[redacted]'


def sanitize_details(value, _depth=0):
    """Recursively strip sensitive keys from an event details payload.

    Returns a JSON-serializable structure safe to persist. Any dict key that
    matches a known sensitive name (case-insensitive) is replaced with
    `[redacted]`; nested dicts/lists are processed recursively. Long strings are
    truncated and values are coerced to JSON-safe primitives.
    """
    if _depth > 6:
        return '[truncated]'
    if isinstance(value, dict):
        safe = {}
        for k, v in value.items():
            if isinstance(k, str) and k.strip().lower() in _SENSITIVE_DETAIL_KEYS:
                safe[k] = _REDACTED
            else:
                safe[k] = sanitize_details(v, _depth + 1)
        return safe
    if isinstance(value, (list, tuple)):
        return [sanitize_details(v, _depth + 1) for v in value]
    if isinstance(value, str):
        return value if len(value) <= 500 else value[:500] + '…'
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:500]


def _dispatch_notifications(app, event):
    """Fan a freshly recorded event out to the matching notification channels.

    The import is lazy because `modules.notifications` imports this module, so a
    top-level import would be circular. Controlled by `NOTIFY_DISPATCH_ON_EVENT`
    (default on). Any failure is logged and swallowed: alerting must never break
    event recording nor the request that produced the event.
    """
    if not app.config.get('NOTIFY_DISPATCH_ON_EVENT', True):
        return
    try:
        from modules.notifications import dispatch_event
        dispatch_event(app, event)
    except Exception as e:
        logger.error(
            f"Notification dispatch failed for event {getattr(event, 'id', None)}: {str(e)}"
        )
        db.session.rollback()


def record_security_event(app, event_type, user_id=None, site_id=None, threat_type=None,
                          method=None, path=None, ip_address=None, decision=None,
                          action_taken=None, confidence=None, rule_id=None, details=None):
    """Persist a single security event (append-only). Returns the new id or None.

    `details` is sanitized before storage so passwords/tokens/request content
    are never written to the database or logs. After a successful commit the
    event is automatically fanned out to matching notification channels; that
    step is best-effort and never affects the stored event.
    """
    import json
    try:
        with app.app_context():
            event = SecurityEvent(
                user_id=user_id,
                site_id=site_id,
                event_type=event_type,
                threat_type=threat_type,
                method=method,
                path=path,
                ip_address=ip_address,
                decision=decision,
                action_taken=action_taken,
                confidence=confidence,
                rule_id=rule_id,
                details=json.dumps(sanitize_details(details)) if details is not None else None
            )
            db.session.add(event)
            db.session.commit()
            # Capture the id before dispatch: a failed dispatch may roll the
            # session back and expire this instance.
            event_id = event.id
            _dispatch_notifications(app, event)
            return event_id
    except Exception as e:
        logger.error(f"Failed to record security event: {str(e)}")
        db.session.rollback()
        return None