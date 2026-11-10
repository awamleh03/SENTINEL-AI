import os
import sys
import re
import logging
import hashlib
import secrets
import datetime
from functools import wraps

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import jwt
import bcrypt
from flask import Blueprint, request, jsonify, current_app
from sqlalchemy.exc import IntegrityError

from modules.database import db, User, PasswordResetToken, record_security_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,80}$")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except (ValueError, TypeError) as e:
        logger.error(f"Password verification error: {str(e)}")
        return False


def generate_token(user, app):
    payload = {
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'exp': datetime.datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')


def decode_token(token, app):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, 'Token has expired'
    except jwt.InvalidTokenError as e:
        return None, f'Invalid token: {str(e)}'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization header is missing'}), 401
        try:
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return jsonify({'error': 'Invalid authorization header format'}), 401
            token = parts[1]
        except (AttributeError, IndexError):
            return jsonify({'error': 'Invalid authorization format'}), 401

        payload, error = decode_token(token, current_app._get_current_object())
        if error:
            return jsonify({'error': error}), 401

        with current_app.app_context():
            user = db.session.get(User, payload.get('user_id'))
            if not user or not user.is_active:
                return jsonify({'error': 'User not found or inactive'}), 401

        request.current_user = user
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if not request.current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


def load_optional_user():
    """Return the authenticated User for a valid bearer token, or None.

    Soft attribution helper for endpoints that also serve anonymous traffic
    (the scanner modules). It never raises and never blocks a request.
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    payload, error = decode_token(parts[1], current_app._get_current_object())
    if error:
        return None
    with current_app.app_context():
        user = db.session.get(User, payload.get('user_id'))
        if not user or not user.is_active:
            return None
    return user


def optional_token_required(f):
    """Like token_required but never rejects the request.

    When a valid token is present, request.current_user is set; otherwise the
    view runs anonymously.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = load_optional_user()
        if user is not None:
            request.current_user = user
        return f(*args, **kwargs)
    return decorated


def validate_password(password: str):
    """Return the list of policy errors for `password` (empty when acceptable).

    Single source of truth for the password policy, shared by registration,
    account settings and password reset.
    """
    if not password:
        return ['Password is required']
    if len(password) < 8:
        return ['Password must be at least 8 characters']
    if not re.search(r'[A-Z]', password):
        return ['Password must contain at least one uppercase letter']
    if not re.search(r'[a-z]', password):
        return ['Password must contain at least one lowercase letter']
    if not re.search(r'\d', password):
        return ['Password must contain at least one digit']
    return []


def validate_user_input(data, require_password=True):
    errors = []
    if not data:
        return ['Request body is required']
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not username:
        errors.append('Username is required')
    elif not USERNAME_REGEX.match(username):
        errors.append('Username must be 3-80 characters and contain only letters, numbers, and ._-')

    if not email:
        errors.append('Email is required')
    elif not EMAIL_REGEX.match(email):
        errors.append('Invalid email format')

    if require_password:
        errors.extend(validate_password(password))

    return errors


@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json(silent=True)
        errors = validate_user_input(data, require_password=True)
        if errors:
            return jsonify({'error': 'Validation failed', 'details': errors}), 400

        username = data['username'].strip()
        email = data['email'].strip()
        password = data['password']

        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing:
            field = 'username' if existing.username == username else 'email'
            return jsonify({'error': f'{field.capitalize()} already exists'}), 409

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            first_name=data.get('first_name', '').strip() or None,
            last_name=data.get('last_name', '').strip() or None
        )
        db.session.add(user)
        db.session.commit()

        token = generate_token(user, current_app._get_current_object())
        user.last_login = datetime.datetime.utcnow()
        db.session.commit()

        logger.info(f"User registered successfully: {username}")
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': user.to_dict()
        }), 201

    except IntegrityError as e:
        logger.error(f"Integrity error on register: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Username or email already exists'}), 409
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed due to server error'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        identifier = (data.get('username') or data.get('email') or '').strip()
        password = data.get('password', '')

        if not identifier or not password:
            return jsonify({'error': 'Identifier and password are required'}), 400

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        if not user or not verify_password(password, user.password_hash):
            logger.warning(f"Failed login attempt for identifier: {identifier}")
            return jsonify({'error': 'Invalid credentials'}), 401

        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 403

        token = generate_token(user, current_app._get_current_object())
        user.last_login = datetime.datetime.utcnow()
        db.session.commit()

        logger.info(f"User logged in successfully: {user.username}")
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed due to server error'}), 500


@auth_bp.route('/me', methods=['GET'])
@token_required
def get_me():
    try:
        return jsonify({
            'user': request.current_user.to_dict()
        }), 200
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        return jsonify({'error': 'Failed to fetch profile'}), 500


@auth_bp.route('/change-password', methods=['POST'])
@token_required
def change_password():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        current_pass = data.get('current_password', '')
        new_pass = data.get('new_password', '')

        if not current_pass or not new_pass:
            return jsonify({'error': 'Current and new passwords are required'}), 400

        user = request.current_user
        if not verify_password(current_pass, user.password_hash):
            return jsonify({'error': 'Current password is incorrect'}), 401

        if len(new_pass) < 8:
            return jsonify({'error': 'New password must be at least 8 characters'}), 400

        user.password_hash = hash_password(new_pass)
        db.session.commit()
        logger.info(f"Password changed for user: {user.username}")
        return jsonify({'message': 'Password changed successfully'}), 200

    except Exception as e:
        logger.error(f"Change password error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to change password'}), 500


def _reset_token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()


def _client_ip_or_none():
    """Best-effort client IP; never raises (safe to call outside a request)."""
    try:
        from modules.events import get_client_ip
        return get_client_ip()
    except Exception:
        return None


def _send_reset_email(app, user, raw_token, ttl_minutes):
    """Best-effort delivery of the reset token. The token is never logged."""
    try:
        from modules.notifications import send_system_email
        subject = 'Sentinel AI password reset'
        body = (
            f"Hello {user.username},\n\n"
            f"Use the token below to reset your password:\n\n{raw_token}\n\n"
            f"It expires in {ttl_minutes} minutes and can be used only once.\n"
            f"If you did not request this, you can safely ignore this email."
        )
        ok, error = send_system_email(app, user.email, subject, body)
        if not ok:
            logger.warning(f"Password reset email not sent for user {user.id}: {error}")
    except Exception as e:
        logger.error(f"Password reset email failed for user {getattr(user, 'id', None)}: {str(e)}")


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Start a password reset.

    Always returns the same generic 200 response, whether or not the email is
    registered, so the endpoint cannot be used to enumerate accounts. When the
    address is valid a single-use token is stored (hashed) and emailed; no raw
    token ever reaches the response body, the logs or the database.
    """
    generic = {'message': 'If that email is registered, a reset link has been sent.'}
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip()
        if not email:
            return jsonify(generic), 200

        app = current_app._get_current_object()
        user = User.query.filter_by(email=email).first()
        if not user or not user.is_active:
            return jsonify(generic), 200

        ttl = app.config.get('PASSWORD_RESET_TOKEN_TTL_MINUTES', 30)
        raw_token = secrets.token_urlsafe(32)
        now = datetime.datetime.utcnow()
        ip = _client_ip_or_none()

        db.session.add(PasswordResetToken(
            user_id=user.id,
            token_hash=_reset_token_hash(raw_token),
            expires_at=now + datetime.timedelta(minutes=ttl),
            requested_ip=ip,
        ))
        db.session.commit()

        _send_reset_email(app, user, raw_token, ttl)
        record_security_event(
            app, event_type='password_reset', user_id=user.id, ip_address=ip,
            path='/api/auth/forgot-password', decision='allow',
            action_taken='reset_requested',
        )
        return jsonify(generic), 200

    except Exception as e:
        logger.error(f"Forgot password error: {str(e)}")
        db.session.rollback()
        # Never surface internal details: keep the response generic.
        return jsonify(generic), 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Complete a password reset with a valid, unused, unexpired token."""
    try:
        data = request.get_json(silent=True) or {}
        raw_token = (data.get('token') or '').strip()
        new_password = data.get('new_password', '')

        if not raw_token:
            return jsonify({'error': 'Token is required'}), 400

        errors = validate_password(new_password)
        if errors:
            return jsonify({'error': 'Validation failed', 'details': errors}), 400

        record = PasswordResetToken.query.filter_by(token_hash=_reset_token_hash(raw_token)).first()
        if not record or not record.is_valid():
            return jsonify({'error': 'Invalid or expired token'}), 400

        user = db.session.get(User, record.user_id)
        if not user or not user.is_active:
            return jsonify({'error': 'Invalid or expired token'}), 400

        user.password_hash = hash_password(new_password)
        record.used_at = datetime.datetime.utcnow()
        db.session.commit()
        logger.info(f"Password reset completed for user: {user.username}")
        return jsonify({'message': 'Password has been reset successfully'}), 200

    except Exception as e:
        logger.error(f"Reset password error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to reset password'}), 500


@auth_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        users = User.query.paginate(page=page, per_page=per_page, error_out=False)
        return jsonify({
            'users': [u.to_dict() for u in users.items],
            'total': users.total,
            'page': page,
            'per_page': per_page
        }), 200
    except Exception as e:
        logger.error(f"List users error: {str(e)}")
        return jsonify({'error': 'Failed to fetch users'}), 500
