import os
import sys
import logging
import datetime
from logging.handlers import RotatingFileHandler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

from backend.config import config_by_name
from modules.database import db, init_db, User, Scan, Alert, save_scan_record
from modules.auth import auth_bp
from modules.docguard import docguard_bp
from modules.mailguard import mailguard_bp
from modules.sysguard import sysguard_bp
from modules.camguard import camguard_bp
from modules.scanguard import scanguard_bp


def _setup_logging(app):
    log_dir = app.config.get('LOG_DIR')
    if log_dir and not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception:
            log_dir = None
    if not app.debug:
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console = logging.StreamHandler()
        console.setFormatter(fmt)
        if log_dir:
            file_handler = RotatingFileHandler(
                os.path.join(log_dir, 'sentinel_ai.log'),
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setFormatter(fmt)
            file_handler.setLevel(logging.INFO)
            if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
                root.addHandler(file_handler)
        if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler) for h in root.handlers):
            root.addHandler(console)
        app.logger.handlers = root.handlers
    app.logger.info(f"SENTINEL-AI starting. ENV={os.environ.get('FLASK_ENV')}. DEBUG={app.debug}")


def _register_blueprints(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(docguard_bp)
    app.register_blueprint(mailguard_bp)
    app.register_blueprint(sysguard_bp)
    app.register_blueprint(camguard_bp)
    app.register_blueprint(scanguard_bp)
    app.logger.info(f"Registered blueprints: "
                    f"{[bp.name for bp in (auth_bp, docguard_bp, mailguard_bp, sysguard_bp, camguard_bp, scanguard_bp)]}")


def _register_frontend_routes(app):
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    frontend_dir = os.path.join(base_dir, 'frontend')

    @app.route('/')
    def serve_index():
        return send_from_directory(frontend_dir, 'index.html')

    @app.route('/dashboard')
    def serve_dashboard():
        return send_from_directory(frontend_dir, 'dashboard.html')

    @app.route('/<path:filename>')
    def serve_static_frontend(filename):
        safe_path = os.path.normpath(os.path.join(frontend_dir, filename))
        if not safe_path.startswith(os.path.normpath(frontend_dir) + os.sep) and safe_path != os.path.normpath(frontend_dir):
            return jsonify({'error': 'Invalid path'}), 400
        if os.path.isfile(safe_path):
            return send_from_directory(frontend_dir, filename)
        return send_from_directory(frontend_dir, 'index.html')


def _register_api_utility_routes(app):
    @app.route('/api/')
    @app.route('/api/health')
    def health_check():
        return jsonify({
            'status': 'ok',
            'service': 'SENTINEL-AI',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'endpoints': {
                'auth': [
                    'POST /api/auth/register',
                    'POST /api/auth/login',
                    'GET  /api/auth/me',
                    'POST /api/auth/change-password',
                    'GET  /api/auth/users (admin)'
                ],
                'docguard': [
                    'POST /api/docguard/scan',
                    'POST /api/docguard/analyze-text'
                ],
                'mailguard': [
                    'POST /api/mailguard/classify',
                    'POST /api/mailguard/batch'
                ],
                'sysguard': [
                    'GET /api/sysguard/status',
                    'GET /api/sysguard/history',
                    'GET /api/sysguard/processes'
                ],
                'camguard': [
                    'POST /api/camguard/analyze',
                    'GET  /api/camguard/health',
                    'POST /api/camguard/reset'
                ],
                'scanguard': [
                    'POST /api/scanguard/analyze',
                    'GET  /api/scanguard/rules'
                ],
                'common': [
                    'GET  /api/scans',
                    'GET  /api/scans/<id>',
                    'GET  /api/alerts',
                    'POST /api/alerts/<id>/read'
                ]
            }
        }), 200

    @app.route('/api/scans', methods=['GET'])
    def list_scans():
        try:
            from modules.auth import token_required
            from flask import g as _g
        except Exception:
            pass
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        module_filter = request.args.get('module')
        min_risk = request.args.get('min_risk', type=float)
        q = Scan.query
        if module_filter:
            q = q.filter(Scan.module == module_filter)
        if min_risk is not None:
            q = q.filter(Scan.risk_score >= min_risk)
        q = q.order_by(Scan.created_at.desc())
        scans = q.paginate(page=page, per_page=per_page, error_out=False)
        return jsonify({
            'scans': [s.to_dict() for s in scans.items],
            'total': scans.total,
            'page': page,
            'per_page': per_page
        }), 200

    @app.route('/api/scans/<int:scan_id>', methods=['GET'])
    def get_scan(scan_id):
        scan = Scan.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(scan.to_dict()), 200

    @app.route('/api/alerts', methods=['GET'])
    def list_alerts():
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 30, type=int), 200)
        severity = request.args.get('severity')
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        source = request.args.get('source')
        q = Alert.query
        if severity:
            q = q.filter(Alert.severity == severity)
        if unread_only:
            q = q.filter(Alert.is_read == False)
        if source:
            q = q.filter(Alert.source == source)
        q = q.order_by(Alert.created_at.desc())
        alerts = q.paginate(page=page, per_page=per_page, error_out=False)
        unread_count = Alert.query.filter(Alert.is_read == False).count()
        return jsonify({
            'alerts': [a.to_dict() for a in alerts.items],
            'total': alerts.total,
            'unread_count': unread_count,
            'page': page,
            'per_page': per_page
        }), 200

    @app.route('/api/alerts/<int:alert_id>/read', methods=['POST'])
    def mark_alert_read(alert_id):
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        alert.is_read = True
        db.session.commit()
        return jsonify({'message': 'Alert marked as read', 'alert': alert.to_dict()}), 200

    @app.route('/api/dashboard/summary', methods=['GET'])
    def dashboard_summary():
        try:
            total_scans = Scan.query.count()
            scans_24h = Scan.query.filter(Scan.created_at >= datetime.datetime.utcnow() - datetime.timedelta(hours=24)).count()
            high_risk_scans = Scan.query.filter(Scan.risk_score >= 40).count()
            critical_scans = Scan.query.filter(Scan.risk_score >= 70).count()
            unread_alerts = Alert.query.filter(Alert.is_read == False).count()
            high_severity_alerts = Alert.query.filter(Alert.severity.in_(['high', 'critical'])).count()
            total_users = User.query.count()
            by_module = db.session.query(
                Scan.module,
                db.func.count(Scan.id),
                db.func.avg(Scan.risk_score),
                db.func.max(Scan.risk_score)
            ).group_by(Scan.module).all()
            module_stats = []
            for m in by_module:
                module_stats.append({
                    'module': m[0],
                    'scan_count': m[1],
                    'avg_risk': round(float(m[2] or 0), 2),
                    'max_risk': round(float(m[3] or 0), 2)
                })
            recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
            recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()
            return jsonify({
                'scans': {
                    'total': total_scans,
                    'last_24h': scans_24h,
                    'high_risk': high_risk_scans,
                    'critical': critical_scans
                },
                'alerts': {
                    'unread': unread_alerts,
                    'high_severity': high_severity_alerts
                },
                'users': {'total': total_users},
                'by_module': module_stats,
                'recent_scans': [s.to_dict() for s in recent_scans],
                'recent_alerts': [a.to_dict() for a in recent_alerts]
            }), 200
        except Exception as e:
            return jsonify({'error': f'Summary failed: {str(e)[:200]}'}), 500


def _register_error_handlers(app):
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({'error': 'Bad request', 'detail': str(e)[:200]}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({'error': 'Unauthorized'}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({'error': 'Forbidden'}), 403

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'API endpoint not found'}), 404
        return e

    @app.errorhandler(413)
    def payload_too_large(e):
        return jsonify({'error': 'Request payload too large'}), 413

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.exception('Internal server error: %s', str(e))
        return jsonify({'error': 'Internal server error'}), 500


def create_app(config_name=None):
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'dev')
    config = config_by_name.get(config_name, config_by_name['dev'])

    app = Flask(__name__,
                static_folder=None,
                template_folder=None)
    app.config.from_object(config)

    upload_dir = app.config.get('UPLOAD_FOLDER')
    if upload_dir:
        os.makedirs(upload_dir, exist_ok=True)

    _setup_logging(app)

    CORS(app, resources={r'/api/*': {
        'origins': '*',
        'supports_credentials': True,
        'expose_headers': ['Content-Length', 'Content-Type'],
        'allow_headers': ['Content-Type', 'Authorization', 'X-Requested-With']
    }})
    app.config['CORS_HEADERS'] = 'Content-Type'

    db.init_app(app)
    init_db(app)

    _register_blueprints(app)
    _register_frontend_routes(app)
    _register_api_utility_routes(app)
    _register_error_handlers(app)

    @app.before_request
    def _log_request():
        if request.path.startswith('/api/'):
            app.logger.info(f"{request.method} {request.path} from {request.remote_addr}")

    app.logger.info("SENTINEL-AI app created successfully.")
    return app


if __name__ == '__main__':
    app = create_app(os.environ.get('FLASK_ENV', 'dev'))
    app.run(host='0.0.0.0', port=5000, debug=True)
