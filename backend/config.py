import os
from datetime import timedelta

class Config:
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'sentinel-ai-dev-secret-key-change-in-production-2024'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'sentinel-ai-jwt-secret-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # AI API Keys configuration
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    GROQ_API_KEY = os.environ.get('GROQ_API_KEY')

    # Pepper (optional) used to strengthen the SHA-256 hash of tenant API keys.
    # Keep it server-side only; it must never be exposed to the browser.
    SENTINEL_API_KEY_PEPPER = os.environ.get('SENTINEL_API_KEY_PEPPER', '')

    # --- Security event log ---------------------------------------------------
    # How long (in days) security events are retained. The purge helper is only
    # ever run explicitly (never automatically), so this is a policy value.
    EVENT_RETENTION_DAYS = int(os.environ.get('EVENT_RETENTION_DAYS', 90))

    # Trusted reverse-proxy configuration. We do NOT blindly trust the
    # X-Forwarded-For header: client IP is only taken from it when the immediate
    # peer (request.remote_addr) is listed here. Comma-separated IPs/CIDRs, e.g.
    #   TRUSTED_PROXIES=10.0.0.1,10.0.0.2
    TRUSTED_PROXIES = [
        p.strip() for p in os.environ.get('TRUSTED_PROXIES', '').split(',') if p.strip()
    ]
    # Number of trusted proxy hops in front of the app (used when parsing the
    # forwarded chain). Defaults to 1 when TRUSTED_PROXIES is set, else 0.
    TRUSTED_PROXY_HOPS = int(
        os.environ.get('TRUSTED_PROXY_HOPS', '1' if TRUSTED_PROXIES else '0')
    )

    # --- Notifications --------------------------------------------------------
    # Default SMTP settings for the email channel. A channel may override these
    # in its own server-side config; per-channel secrets are never sent to the
    # browser. When SMTP is not configured, email channels fail closed (test
    # sends report a clear "not configured" error rather than pretending).
    ALERT_SMTP_HOST = os.environ.get('ALERT_SMTP_HOST', '')
    ALERT_SMTP_PORT = int(os.environ.get('ALERT_SMTP_PORT', 587))
    ALERT_SMTP_USER = os.environ.get('ALERT_SMTP_USER', '')
    ALERT_SMTP_PASSWORD = os.environ.get('ALERT_SMTP_PASSWORD', '')
    ALERT_SMTP_FROM = os.environ.get('ALERT_SMTP_FROM', '')
    ALERT_SMTP_USE_TLS = os.environ.get('ALERT_SMTP_USE_TLS', 'true').lower() == 'true'
    ALERT_SMTP_TIMEOUT = int(os.environ.get('ALERT_SMTP_TIMEOUT', 10))

    # Aggregation window (seconds) used to collapse repeated identical events
    # into a single notification so users are not flooded by bursts.
    NOTIFY_DEDUP_WINDOW_SECONDS = int(os.environ.get('NOTIFY_DEDUP_WINDOW_SECONDS', 300))

    # When True, notification transports are not actually invoked (messages are
    # recorded with status 'skipped'). Tests enable this so no real messages are
    # ever sent without explicit approval.
    NOTIFY_DRY_RUN = os.environ.get('NOTIFY_DRY_RUN', 'false').lower() == 'true'

    # When True, every recorded security event is automatically fanned out to
    # the enabled+verified notification channels that match its severity. Set to
    # False to record events silently (e.g. during a bulk import or backfill)
    # without touching the dispatch code.
    NOTIFY_DISPATCH_ON_EVENT = os.environ.get('NOTIFY_DISPATCH_ON_EVENT', 'true').lower() == 'true'

    # Lifetime (minutes) of a password-reset token. Tokens are single-use and
    # always stored hashed; the raw token is only ever sent to the user.
    PASSWORD_RESET_TOKEN_TTL_MINUTES = int(os.environ.get('PASSWORD_RESET_TOKEN_TTL_MINUTES', 30))

    # Connection string is driven entirely by the DATABASE_URL environment
    # variable. No credentials are hardcoded in source. When DATABASE_URL is
    # absent we fall back to a local SQLite file for development.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or (
        'sqlite:///' + os.path.join(BASE_DIR, 'sentinel.db')
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Connection pool tuning, suitable for a production PostgreSQL deployment.
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.environ.get('DB_POOL_SIZE', 10)),
        'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', 20)),
        'pool_timeout': int(os.environ.get('DB_POOL_TIMEOUT', 30)),
        'pool_recycle': int(os.environ.get('DB_POOL_RECYCLE', 1800)),
        'pool_pre_ping': True,
    }
    CORS_HEADERS = 'Content-Type'
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'pdf', 'txt', 'log', 'py', 'js', 'html', 'csv', 'json'}
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    SYSGUARD_HISTORY_SIZE = 60
    SYSGUARD_ANOMALY_THRESHOLD = 2.0

    # --- Bot detection (monitor-only, phase 1) --------------------------------
    # Heuristic thresholds combined into a suspicion score. No single signal is
    # decisive and nothing is ever blocked in this phase. All values are tunable.
    BOT_SUSPICION_THRESHOLD = int(os.environ.get('BOT_SUSPICION_THRESHOLD', 40))
    # Sliding window (seconds) used to measure the recent request burst.
    BOT_WINDOW_SECONDS = int(os.environ.get('BOT_WINDOW_SECONDS', 10))
    # Requests within the window at or above this count raise `high_request_rate`.
    BOT_RATE_THRESHOLD = int(os.environ.get('BOT_RATE_THRESHOLD', 20))
    # Number of consecutive intervals sampled for regularity detection.
    BOT_INTERVAL_MIN_SAMPLES = int(os.environ.get('BOT_INTERVAL_MIN_SAMPLES', 6))
    BOT_INTERVAL_SAMPLE_LIMIT = int(os.environ.get('BOT_INTERVAL_SAMPLE_LIMIT', 20))
    # Intervals (ms) whose standard deviation is at or below this look machine-paced.
    BOT_INTERVAL_MAX_STDEV_MS = float(os.environ.get('BOT_INTERVAL_MAX_STDEV_MS', 50))

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///sentinel_dev.db'
 

class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_ENGINE_OPTIONS = {}
    SERVER_NAME = 'localhost'
    # Never invoke real notification transports during tests.
    NOTIFY_DRY_RUN = True

config_by_name = {
    'dev': DevelopmentConfig,
    'prod': ProductionConfig,
    'test': TestingConfig
}