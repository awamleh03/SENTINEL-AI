import os
import sys
import logging
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship

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


def save_alert_record(app, user_id, source, severity, title, message, alert_metadata=None):
    import json
    try:
        with app.app_context():
            alert = Alert(
                user_id=user_id,
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
