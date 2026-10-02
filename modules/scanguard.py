import os
import sys
import re
import logging
import datetime
import requests
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

from modules.database import save_scan_record, save_alert_record

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

scanguard_bp = Blueprint('scanguard', __name__, url_prefix='/api/scanguard')

SQLI_PATTERNS = [
    (r"(?i)(\b(OR|AND)\b\s+['\"]?[0-9a-fA-F]+['\"]?\s*=\s*['\"]?[0-9a-fA-F]+)",
        'Tautology-based SQLi (OR 1=1 pattern)', 95),
    (r"(?i)(\bUNION\b\s+\b(ALL\s+)?\bSELECT\b)",
        'UNION SELECT injection pattern', 95),
    (r"(?i)\bDROP\b\s+\b(TABLE|DATABASE)\b",
        'Destructive DROP statement', 100),
    (r"(?i)\bINSERT\b\s+\bINTO\b.*\bVALUES\b",
        'INSERT statement (unexpected in input)', 70),
    (r"(?i)\bDELETE\b\s+\bFROM\b",
        'DELETE statement (unexpected in input)', 85),
    (r"(?i)\bUPDATE\b.*\bSET\b",
        'UPDATE statement (unexpected in input)', 80),
    (r"(?i)(;|--|#\s|/\*|\*/)",
        'SQL comment/terminator (risk of stacked queries)', 55),
    (r"(?i)\bWAITFOR\b\s+\bDELAY\b|\bSLEEP\s*\(",
        'Time-based blind SQLi', 90),
    (r"(?i)\b(BENCHMARK|CONVERT|CAST|CHAR|0x[0-9a-f]{4,})\b",
        'Encoding/obfuscation (likely SQLi probe)', 75),
    (r"(?i)\bINFORMATION_SCHEMA\b|\bTABLE_SCHEMA\b|\bCOLUMNS\b",
        'Schema enumeration pattern', 90),
    (r"(?i)(?:\bor\b|\band\b)[\s\(]+[^\s]*?=.*(--|#)",
        'Boolean-based blind SQLi', 85)
]

XSS_PATTERNS = [
    (r"(?i)<\s*script[^>]*>",
        '<script> tag — direct XSS', 95),
    (r"(?i)javascript\s*:",
        'javascript: URL scheme', 90),
    (r"(?i)on\w+\s*=\s*[\"']",
        'Inline event handler (onclick, onerror, onload...)', 85),
    (r"(?i)<\s*iframe[^>]*>",
        '<iframe> tag (possible sandbox escape / clickjacking)', 60),
    (r"(?i)<\s*img[^>]*\s+src\s*=\s*[\"']\s*[^\"']*?(onerror|onload|javascript)",
        'img with malicious attr XSS', 90),
    (r"(?i)(&#x[0-9a-f]+;|&#\d+;)",
        'HTML entity encoding (possible XSS obfuscation)', 45),
    (r"(?i)</?\s*(svg|object|embed|form|input|base|link)[^>]*>",
        'Suspicious HTML tag (XSS / UI redress)', 55),
    (r"(?i)(document\.(cookie|location|domain|write)|eval\s*\(|setTimeout\s*\(.*['\"])",
        'Suspicious DOM / code-exec JS', 75)
]

SECRET_PATTERNS = [
    (r"(?i)(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']",
        'Hardcoded API key / token in code', 85),
    (r"(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        'Private key PEM block', 100),
    (r"(?i)(AKIA[0-9A-Z]{16})",
        'AWS Access Key ID pattern', 95),
    (r"(?i)(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})",
        'GitHub Personal Access Token', 95),
    (r"(?i)(sk-(?:live|test)-[A-Za-z0-9]{20,})",
        'Stripe secret key pattern', 95),
    (r"(?i)(xox[baprs]-[A-Za-z0-9-]{10,})",
        'Slack bot / user token', 90),
    (r"AIza[0-9A-Za-z\-_]{35}",
        'Google API key pattern', 90),
    (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']",
        'Hardcoded plaintext password', 80),
    (r"(?i)(?:mongodb|postgres|mysql|redis):\/\/[^:@\s]+:[^@\s]+@",
        'Connection string with embedded credentials', 95),
    (r"\b[A-Za-z0-9+/]{80,}={0,2}\b",
        'Long base64 blob (possible embedded secret / payload)', 40)
]

LOG_PATTERNS = [
    (r"(?i)\b(ERROR|FATAL|CRITICAL|EMERGENCY|SEVERE|EXCEPTION|Traceback|panic)\b",
        'Error-level log entry', 40),
    (r"(?i)\b(unauthorized|access denied|permission denied|invalid password|failed login|401|403)\b",
        'Auth failure in logs', 60),
    (r"(?i)\b(sql|mysql|ora-|pg_|syntax error|constraint violation|duplicate key)\b.*\b(error|fail|exception)",
        'Database error (possible SQLi / data issues)', 50),
    (r"(?i)\b(out of memory|oom|segmentation fault|segfault|core dumped|stack overflow|fatal error)\b",
        'Severe stability issue', 70),
    (r"(?i)\b(dos|ddos|brute force|intrusion|attack|suspicious|blocked)\b",
        'Security incident indicator in logs', 75),
    (r"(?i)\b(rce|remote code|command injection|shell|exec|reverse shell|bind shell|backdoor)\b",
        'RCE / shell indicator in logs', 95),
    (r"(?i)(http(s?)://\S+)\s+(4\d{2}|5\d{2})\b",
        'Repeated 4xx/5xx (possible scanning)', 30)
]

GENERIC_RULES = [
    (r"(?i)\b(system|exec|shell|os\.system|subprocess\.call|popen|eval|Runtime\.getRuntime)\s*\(",
        'Command execution function (RCE risk if input flows here)', 75),
    (r"(?i)(base64_decode|atob|decodeURIComponent|unescape)\s*\(",
        'Runtime decode function (may hide payload)', 45),
    (r"(?i)\b(TODO|FIXME|HACK|XXX|BUG)\b",
        'Poor code hygiene marker (informational)', 10),
    (r"(?i)\b(chmod\s+777|chown\s+[^:]+:root|sudo |su root)",
        'Excessive permissions / privilege abuse', 70),
    (r"(?i)\beval\s*\(.*(\$_GET|\$_POST|\$_REQUEST|request\[|params\[)",
        'Eval with user input (classic RCE)', 95)
]


def _scan_with_patterns(text, pattern_list):
    findings = []
    line_offset = []
    if text:
        line_offset.append(0)
        for m in re.finditer(r'\n', text):
            line_offset.append(m.end())

    def _lineno(abs_pos):
        lo, hi = 0, len(line_offset) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_offset[mid] <= abs_pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    for pattern, description, severity in pattern_list:
        try:
            for match in re.finditer(pattern, text, re.DOTALL if '\\n' in pattern or pattern.endswith('.*') else 0):
                findings.append({
                    'rule': description,
                    'severity_points': severity,
                    'match': match.group(0)[:180],
                    'line': _lineno(match.start()),
                    'column': match.start() - (line_offset[_lineno(match.start()) - 1] if _lineno(match.start()) <= len(line_offset) else 0)
                })
        except re.error as e:
            logger.warning(f"ScanGuard regex error on pattern '{pattern[:60]}': {str(e)}")
    return findings


def _code_stats(text):
    if not text:
        return {}
    lines = text.split('\n')
    line_count = len(lines)
    blank = sum(1 for l in lines if not l.strip())
    comments = sum(1 for l in lines if re.match(r'^\s*(#|//|/\*|\*|\--)\b', l))
    long_lines = sum(1 for l in lines if len(l) > 200)
    return {
        'total_lines': line_count,
        'blank_lines': blank,
        'comment_lines': comments,
        'code_lines': line_count - blank - comments,
        'lines_over_200_chars': long_lines,
        'size_bytes': len(text.encode('utf-8', 'replace'))
    }


def analyze_code_ai(code_snippet=None, log_content=None):
    api_key = os.getenv('OPENAI_API_KEY') or os.getenv('GROQ_API_KEY')
    if not api_key:
        return None
    
    is_groq = bool(os.getenv('GROQ_API_KEY')) and not os.getenv('OPENAI_API_KEY')
    url = "https://api.groq.com/openai/v1/chat/completions" if is_groq else "https://api.openai.com/v1/chat/completions"
    model = "llama-3.3-70b-versatile" if is_groq else "gpt-4o-mini"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    system_prompt = (
        "You are an expert application security engineer and static code analysis tool. "
        "Analyze the provided code snippet or log content for security vulnerabilities such as SQLi, XSS, "
        "hardcoded secrets, insecure deserialization, remote code execution, or dangerous functions. "
        "Return a valid JSON object with keys: "
        "'vulnerabilities' (list of objects containing 'type', 'severity' (low/medium/high/critical), 'description', 'line_or_context', 'remediation'), "
        "'risk_score' (float between 0 and 100), "
        "'risk_level' (low/medium/high/critical), "
        "'summary' (string)."
    )
    
    target_content = f"Code Snippet:\n{code_snippet or ''}\n\nLog Content:\n{log_content or ''}"
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": target_content}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        if response.status_code == 200:
            res_json = response.json()
            content = res_json['choices'][0]['message']['content']
            return json.loads(content)
    except Exception as e:
        logger.error(f"AI Code Analysis error: {str(e)}")
    return None


def analyze_code_or_log(text, input_type='auto', filename=None):
    # Try AI-powered analysis first if available
    ai_result = analyze_code_ai(
        code_snippet=text if input_type != 'log' else None,
        log_content=text if input_type == 'log' else None
    )
    if ai_result and 'risk_score' in ai_result:
        risk_score = float(ai_result.get('risk_score', 0.0))
        level = ai_result.get('risk_level', 'low')
        if not level:
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
            'detected_input_type': input_type,
            'risk_score': risk_score,
            'risk_level': level,
            'total_issues_found': len(ai_result.get('vulnerabilities', [])),
            'ai_summary': ai_result.get('summary', ''),
            'vulnerabilities': ai_result.get('vulnerabilities', []),
            'stats': _code_stats(text),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }

    results_by_category = {
        'sqli': [],
        'xss': [],
        'secrets': [],
        'log_issues': [],
        'generic_issues': []
    }
    text = text or ''
    code_like_indicators = sum(
        1 for p in (';', '{', '}', 'def ', 'function ', 'class ', 'import ',
                    '#include', '<script', 'SELECT ', 'from ', '=')
        if p in text
    )
    log_like_indicators = sum(
        1 for p in ('ERROR', 'WARN', 'INFO', 'DEBUG', 'FATAL', '2024-',
                    '2025-', '2026-', '[', ']', '::', ' | ', ' at ', ' PID ', 'thread-')
        if p in text
    )
    if input_type == 'auto':
        if log_like_indicators > code_like_indicators and ('ERROR' in text or 'WARN' in text or 'INFO' in text):
            detected_type = 'log'
        else:
            detected_type = 'code'
    else:
        detected_type = input_type

    results_by_category['sqli'] = _scan_with_patterns(text, SQLI_PATTERNS)
    results_by_category['xss'] = _scan_with_patterns(text, XSS_PATTERNS)
    results_by_category['secrets'] = _scan_with_patterns(text, SECRET_PATTERNS)

    if detected_type == 'log':
        results_by_category['log_issues'] = _scan_with_patterns(text, LOG_PATTERNS)
    results_by_category['generic_issues'] = _scan_with_patterns(text, GENERIC_RULES)

    total_findings = 0
    weighted_score = 0.0
    for cat, items in results_by_category.items():
        total_findings += len(items)
        for f in items:
            w = {'sqli': 1.0, 'xss': 1.0, 'secrets': 1.2,
                 'log_issues': 0.6, 'generic_issues': 0.7}.get(cat, 0.8)
            weighted_score += f['severity_points'] * w

    risk_score = min(round(weighted_score / 2.0, 2), 100)
    if total_findings == 0:
        risk_score = 0
    if risk_score >= 70:
        level = 'critical'
    elif risk_score >= 40:
        level = 'high'
    elif risk_score >= 15:
        level = 'medium'
    else:
        level = 'low'

    category_summary = {
        cat: {
            'count': len(items),
            'severity_sum': sum(f['severity_points'] for f in items),
            'top_issue': max(items, key=lambda x: x['severity_points'])['rule'] if items else None
        }
        for cat, items in results_by_category.items()
    }

    return {
        'filename': filename,
        'detected_input_type': detected_type,
        'risk_score': risk_score,
        'risk_level': level,
        'total_issues_found': total_findings,
        'category_summary': category_summary,
        'findings': results_by_category,
        'stats': _code_stats(text),
        'timestamp': datetime.datetime.utcnow().isoformat()
    }


def _load_input_from_request():
    file = request.files.get('file')
    if file:
        filename = file.filename
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        try:
            raw = file.read()
            text = raw.decode('utf-8', errors='replace')
        except Exception as e:
            return None, None, f'Failed to read uploaded file: {str(e)[:100]}'
        log_exts = {'log', 'txt', 'out', 'err'}
        itype = 'log' if ext in log_exts else 'code'
        return text, filename, None
    data = request.get_json(silent=True)
    if data and ('code' in data or 'text' in data or 'log' in data or 'content' in data):
        text = data.get('code') or data.get('text') or data.get('log') or data.get('content') or ''
        filename = data.get('filename')
        itype = data.get('type', 'auto')
        if data.get('code') is not None:
            itype = 'code'
        if data.get('log') is not None:
            itype = 'log'
        return text, filename, None
    raw = request.get_data(cache=False)
    if raw and len(raw) > 0:
        try:
            return raw.decode('utf-8', errors='replace'), 'raw_payload.txt', None
        except Exception:
            return None, None, 'Could not decode request payload as UTF-8'
    return None, None, ('No input provided. Upload a file as "file", '
                         'or send JSON with "code"/"text"/"log"/"content" field.')


@scanguard_bp.route('/analyze', methods=['POST'])
def analyze():
    try:
        text, filename, error = _load_input_from_request()
        if error:
            return jsonify({'error': error}), 400
        if not isinstance(text, str) or len(text) == 0:
            return jsonify({'error': 'Empty input received'}), 400
        if len(text) > 10 * 1024 * 1024:
            return jsonify({'error': 'Input exceeds 10MB limit'}), 413
        result = analyze_code_or_log(text, filename=filename)
        user_id = getattr(request, 'current_user', None)
        user_id = user_id.id if user_id else None
        scan_id = save_scan_record(
            current_app._get_current_object(),
            user_id=user_id,
            module='scanguard',
            target=(filename or '')[:200],
            risk_score=result['risk_score'],
            details={
                'risk_level': result['risk_level'],
                'category_summary': result.get('category_summary', {}),
                'total_issues': result['total_issues_found']
            },
            raw_input_size=len(text)
        )
        result['scan_id'] = scan_id
        if result['risk_score'] >= 40:
            save_alert_record(
                current_app._get_current_object(),
                user_id=user_id,
                source='scanguard',
                severity='high' if result['risk_score'] >= 70 else 'medium',
                title=f'ScanGuard: {result["risk_level"].capitalize()} risk detected',
                message=(f'{result["total_issues_found"]} issues found in {filename or "input"}.'),
                alert_metadata={'scan_id': scan_id}
            )
        logger.info(f"ScanGuard analyze: {result['total_issues_found']} issues, risk={result['risk_score']}")
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"ScanGuard analyze error: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)[:200]}'}), 500


@scanguard_bp.route('/rules', methods=['GET'])
def rules_info():
    info = {
        'sqli': len(SQLI_PATTERNS),
        'xss': len(XSS_PATTERNS),
        'secrets': len(SECRET_PATTERNS),
        'log_issues': len(LOG_PATTERNS),
        'generic_issues': len(GENERIC_RULES),
        'total_rules': len(SQLI_PATTERNS) + len(XSS_PATTERNS) + len(SECRET_PATTERNS) \
                        + len(LOG_PATTERNS) + len(GENERIC_RULES)
    }
    return jsonify({'rules': info,
                    'descriptions': {
                        'sqli': [r[1] for r in SQLI_PATTERNS],
                        'xss': [r[1] for r in XSS_PATTERNS],
                        'secrets': [r[1] for r in SECRET_PATTERNS],
                        'log_issues': [r[1] for r in LOG_PATTERNS],
                        'generic_issues': [r[1] for r in GENERIC_RULES]
                    }}), 200