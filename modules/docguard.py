import os
import sys
import re
import io
import logging
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

try:
    try:
        from pypdf import PdfReader as _PdfReader
        PdfReader = _PdfReader
    except ImportError:
        from PyPDF2 import PdfReader as _PdfReader
        PdfReader = _PdfReader
except ImportError:
    PdfReader = None

from modules.database import db, save_scan_record

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

docguard_bp = Blueprint('docguard', __name__, url_prefix='/api/docguard')

SUSPICIOUS_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
    'adf.ly', 'shorte.st', 'bc.vc', 'adfoc.us', 'j.gs', 'q.gs',
    'paypal-login', 'bank', 'verify', 'update', 'secure-login', 'account-update',
    'password-reset', 'account-verify',
    'phish', 'malware', 'ransom', 'attack', 'exploit', 'hack'
]

DANGER_KEYWORDS_EN = [
    'ransom', 'ransomware', 'malware', 'virus', 'trojan', 'worm',
    'backdoor', 'exploit', 'payload', 'infect', 'compromise', 'breach',
    'credit card', 'ssn', 'social security', 'password', 'confidential',
    'secret', 'proprietary', 'classified', 'top secret',
    'transfer', 'wire transfer', 'bank account', 'routing number',
    'urgent', 'immediate', 'asap', 'critical', 'emergency',
    'bitcoin', 'crypto', 'wallet', 'private key', 'seed phrase',
    'click here', 'download now', 'open attachment', 'enable macros',
    'social insurance number', 'date of birth', 'mother maiden name'
]

DANGER_KEYWORDS_AR = [
    'فدية', 'برامج ضارة', 'فيروس', 'خداع', 'اختراق', 'اخترق',
    'تهديد', 'مخترق', 'مواد خبيثة', 'دودة', 'حصان طروادة',
    'بطاقة ائتمان', 'رقم البطاقة', 'رقم سري', 'كلمة مرور',
    'سري', 'سرّي', 'مصنف', 'سري للغاية', 'مملوكة',
    'تحويل بنكي', 'رقم حساب', 'رقم الحساب', 'تحويل مالي',
    'عاجل', 'فوري', 'حرج', 'طوارئ',
    'عملات رقمية', 'بيتكوين', 'محفظة رقمية',
    'اضغط هنا', 'قم بالتنزيل', 'افتح المرفق', 'تفعيل الماكرو',
    'رقم الهوية', 'تاريخ الميلاد', 'اسم الأم'
]

URL_REGEX = re.compile(
    r'(https?://[^\s<>\"]+|www\.[^\s<>\"]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>\"]*)?)',
    re.IGNORECASE
)

CREDIT_CARD_REGEX = re.compile(
    r'\b(?:\d[ -]*?){13,19}\b'
)


def _luhn_check(number_str):
    number_str = re.sub(r'[^\d]', '', number_str)
    if len(number_str) < 13 or len(number_str) > 19:
        return False
    try:
        digits = [int(d) for d in number_str]
        checksum = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0
    except (ValueError, TypeError):
        return False


def extract_text_from_pdf(file_storage=None, file_bytes=None):
    text_parts = []
    errors = []
    if PdfReader is None:
        return '', ['PyPDF2 library is not available']
    try:
        if file_bytes is not None:
            reader = PdfReader(io.BytesIO(file_bytes))
        elif file_storage is not None:
            reader = PdfReader(io.BytesIO(file_storage.read()))
        else:
            return '', ['No input provided']

        num_pages = len(reader.pages)
        for page_num in range(min(num_pages, 100)):
            try:
                page_text = reader.pages[page_num].extract_text() or ''
                text_parts.append(page_text)
            except Exception as e:
                errors.append(f'Page {page_num + 1}: {str(e)[:100]}')
    except Exception as e:
        logger.error(f"PDF extraction error: {str(e)}")
        return '', [f'Failed to parse PDF: {str(e)[:200]}']
    return '\n'.join(text_parts), errors


def find_suspicious_urls(text):
    findings = []
    if not text:
        return findings
    matches = URL_REGEX.findall(text)
    seen = set()
    for match in matches:
        url_lower = match.lower()
        if url_lower in seen:
            continue
        seen.add(url_lower)
        reasons = []
        risk = 0
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url_lower:
                reasons.append(f'Matches suspicious domain pattern: {domain}')
                risk += 30
        if url_lower.startswith('http://') and not url_lower.startswith('https://'):
            reasons.append('Non-HTTPS (unencrypted connection')
            risk += 15
        if re.search(r'@', match):
            reasons.append('Contains @ symbol (potential phishing redirect)')
            risk += 25
        if re.search(r'\d{1,3}(?:\.\d{1,3}){3}', match):
            reasons.append('Contains IP address instead of domain')
            risk += 20
        if len(match) > 80:
            reasons.append('Unusually long URL')
            risk += 10
        if reasons:
            findings.append({
                'url': match[:200],
                'risk': min(risk, 100),
                'reasons': reasons
            })
    return findings


def find_credit_cards(text):
    findings = []
    if not text:
        return findings
    matches = CREDIT_CARD_REGEX.findall(text)
    seen = set()
    for match in matches:
        digits_only = re.sub(r'[^\d]', '', match)
        if digits_only in seen:
            continue
        seen.add(digits_only)
        if _luhn_check(match):
            masked = digits_only[:4] + '*' * (len(digits_only) - 8) + digits_only[-4:]
            findings.append({
                'card_number_masked': masked,
                'length': len(digits_only),
                'risk': 95
            })
    return findings


def find_dangerous_keywords(text):
    findings = []
    if not text:
        return findings
    text_lower = text.lower()
    for kw in DANGER_KEYWORDS_EN:
        count = len(re.findall(r'\b' + re.escape(kw) + r'\b', text_lower))
        if count > 0:
            findings.append({
                'keyword': kw,
                'language': 'en',
                'count': count,
                'risk': min(15 * count, 50)
            })
    for kw in DANGER_KEYWORDS_AR:
        count = text_lower.count(kw.lower())
        if count > 0:
            findings.append({
                'keyword': kw,
                'language': 'ar',
                'count': count,
                'risk': min(15 * count, 50)
            })
    return findings


def analyze_text(text, filename=None):
    issues = {
        'suspicious_urls': find_suspicious_urls(text),
        'credit_cards': find_credit_cards(text),
        'dangerous_keywords': find_dangerous_keywords(text)
    }
    url_risk = sum(item['risk'] for item in issues['suspicious_urls'])
    cc_risk = sum(item['risk'] for item in issues['credit_cards'])
    kw_risk = sum(item['risk'] for item in issues['dangerous_keywords'])
    base_risk = url_risk * 0.5 + cc_risk * 0.9 + kw_risk * 0.3
    risk_score = min(round(base_risk, 2), 100)
    if risk_score >= 70:
        level = 'critical'
    elif risk_score >= 40:
        level = 'high'
    elif risk_score >= 15:
        level = 'medium'
    else:
        level = 'low'
    return {
        'filename': filename,
        'text_length': len(text or ''),
        'risk_score': risk_score,
        'risk_level': level,
        'issues_found': len(issues['suspicious_urls']) + len(issues['credit_cards']) + len(issues['dangerous_keywords']),
        'issues': issues
    }


@docguard_bp.route('/scan', methods=['POST'])
def scan_pdf():
    file = request.files.get('file')
    user_id = getattr(request, 'current_user', None)
    user_id = user_id.id if user_id else None
    if not file:
        raw_json = request.get_json(silent=True)
        if raw_json and 'text' in raw_json:
            text = raw_json.get('text', '')
            filename = raw_json.get('filename', 'raw_text')
        else:
            return jsonify({'error': 'No file uploaded. Send a PDF file as form-data with key "file" or provide raw JSON with "text" field'}), 400
        text_extraction_errors = []
    else:
        filename = file.filename
        allowed = {'pdf', 'txt'}
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if ext not in allowed:
            return jsonify({'error': f'Unsupported file type. Allowed: PDF, TXT'}), 400
        if ext == 'pdf':
            text, text_extraction_errors = extract_text_from_pdf(file_storage=file)
        else:
            try:
                text = file.read().decode('utf-8', errors='replace')
                text_extraction_errors = []
            except Exception as e:
                return jsonify({'error': f'Failed to read text file: {str(e)[:200]}'}), 400
    try:
        result = analyze_text(text, filename=filename)
        if text_extraction_errors:
            result['extraction_warnings'] = text_extraction_errors
        scan_id = save_scan_record(
            current_app._get_current_object(),
            user_id=user_id,
            module='docguard',
            target=filename,
            risk_score=result['risk_score'],
            details=result,
            raw_input_size=len(text or '')
        )
        result['scan_id'] = scan_id
        logger.info(f"DocGuard scan completed for {filename}: risk={result['risk_score']}")
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"DocGuard scan error: {str(e)}")
        return jsonify({'error': f'Scan failed: {str(e)[:200]}'}), 500


@docguard_bp.route('/analyze-text', methods=['POST'])
def analyze_text_endpoint():
    data = request.get_json(silent=True)
    if not data or 'text' not in data:
        return jsonify({'error': 'Request body must include "text" field'}), 400
    text = data.get('text', '')
    try:
        result = analyze_text(text, filename=data.get('filename', 'raw_text_input'))
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"DocGuard analyze-text error: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)[:200]}'}), 500
