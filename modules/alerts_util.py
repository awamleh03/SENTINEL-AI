"""ضع هذا الملف في: modules/alerts_util.py"""
import logging

logger = logging.getLogger(__name__)


def save_module_alert(app, *, user_id, source, risk_score, title, message, scan_id=None, extra=None):
    if risk_score is None:
        return None
    try:
        score = float(risk_score)
    except (TypeError, ValueError):
        return None
    if score < 40:
        return None
    try:
        from modules.database import save_alert_record
        severity = 'high' if score >= 70 else 'medium'
        meta = {'risk_score': score}
        if scan_id is not None:
            meta['scan_id'] = scan_id
        if extra and isinstance(extra, dict):
            meta.update(extra)
        return save_alert_record(
            app,
            user_id=user_id,
            source=source,
            severity=severity,
            title=title[:200] if title else f'{source} alert',
            message=(message or '')[:500],
            alert_metadata=meta,
        )
    except Exception as e:
        logger.warning(f'Alert save skipped ({source}): {e}')
        return None
