import os
import sys
import re
import logging
import datetime
import requests
import json
from collections import Counter

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, request, jsonify, current_app

from modules.database import save_scan_record, save_alert_record

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mailguard_bp = Blueprint('mailguard', __name__, url_prefix='/api/mailguard')

SPAM_KEYWORDS_EN = {
    'free': 3, 'win': 4, 'winner': 4, 'won': 4, 'prize': 5, 'congratulations': 3,
    'congrats': 3, 'offer': 3, 'limited': 2, 'exclusive': 2, 'urgent': 3,
    'now': 2, 'today': 2, 'only': 2, 'guaranteed': 4, '100%': 3, 'free money': 5,
    'click here': 4, 'buy now': 4, 'act now': 4, 'discount': 2, 'sale': 2,
    'cheap': 3, 'lowest': 3, 'bargain': 3, 'investment': 4, 'million': 4,
    'cash': 3, 'money': 3, 'income': 4, 'profit': 4, 'lottery': 5,
    'loan': 3, 'credit': 2, 'debt': 2, 'mortgage': 3, 'insurance': 2,
    'claim': 3, 'redeem': 3, 'subscribe': 2, 'unsubscribe': -1,
    'viagra': 5, 'pharmacy': 4, 'meds': 4, 'pills': 4, 'weight loss': 4,
    'diet': 3, 'enlarge': 5, 'replica': 5, 'rolex': 5, 'fake': 5,
    'dating': 2, 'singles': 3, 'hot': 2, 'sexy': 4, 'nude': 5,
    'bank': 2, 'paypal': 3, 'verify': 4, 'confirm': 3, 'update': 3,
    'account': 3, 'password': 3, 'login': 3, 'security': 3,
    'dear friend': 4, 'my dear': 3, 'beloved': 3, 'greetings': 2,
    'unknown sender': 3, 'no subject': 2, 'forwarded': 1, 'attach': 2,
    'download': 3, 'attachment': 3, 'invoice': 3, 'statement': 3,
    'irs': 4, 'government': 3, 'fbi': 4, 'police': 3, 'court': 4,
    'nigeria': 5, 'lagos': 5, 'western union': 5, 'moneygram': 5,
    'urgent help': 5, 'stranded': 4, 'send money': 5, 'wire': 4,
    'bitcoin': 3, 'crypto': 3, 'wallet': 3, 'private key': 5,
    'malware': 2, 'virus': 2, 'suspended': 4, 'terminated': 4
}

PHISHING_KEYWORDS_EN = {
    'verify your account': 8, 'confirm your identity': 8, 'account suspended': 8,
    'account compromised': 9, 'unusual activity': 7, 'security alert': 7,
    'please confirm': 6, 'click to verify': 8, 'login to confirm': 8,
    'update your billing': 7, 'payment failed': 6, 'payment declined': 6,
    'verify purchase': 7, 'your account will be': 7, 'within 24 hours': 6,
    'immediate action required': 8, 'failure to comply': 7,
    'reset your password': 5, 'password expired': 6,
    'dear customer': 5, 'dear user': 4, 'valued customer': 4,
    'this is an official': 4, 'authorized representative': 5,
    'we noticed a login': 7, 'new sign-in attempt': 7,
    'someone has your password': 9, 'your password was leaked': 9,
    'apple id': 6, 'google account': 6, 'microsoft account': 6,
    'amazon': 6, 'ebay': 5, 'netflix': 5, 'spotify': 5,
    'your package': 5, 'delivery failed': 5, 'shipping': 4,
    'fedex': 5, 'ups': 5, 'dhl': 5, 'usps': 5,
    'http://': 4, 'bit.ly': 6, 'tinyurl': 6, 'short link': 3,
    'attachment': 3, 'open the attached': 5, 'download document': 5,
    'enable macros': 9, 'office 365': 4, 'sharepoint': 4,
    'onedrive': 4, 'dropbox': 5, 'google drive': 5
}

URGENT_KEYWORDS_EN = {
    'urgent': 6, 'asap': 5, 'immediately': 5, 'now': 3, 'today': 2,
    'this morning': 3, 'tonight': 3, 'right away': 5, 'at once': 5,
    '24 hours': 4, '48 hours': 3, 'deadline': 5, 'expires': 4,
    'last chance': 5, 'final notice': 6, 'final warning': 6,
    'critical': 5, 'emergency': 6, 'important': 2, 'time sensitive': 5,
    'before it': 3, 'don\'t miss': 3, 'limited time': 4,
    'act now': 5, 'do not delay': 5, 'without delay': 5,
    'fire': 7, 'breach': 7, 'compromise': 7, 'leak': 7,
    'help me': 5, 'please help': 4, 'stuck': 3, 'need you': 3,
    'can you send': 4, 'can you buy': 5, 'i need you to': 4,
    'ceo': 5, 'boss': 3, 'director': 3, 'president': 3, 'hr': 3,
    'confidential': 4, 'between us': 4, 'do not share': 4,
    'quick favor': 5, 'personal matter': 3
}

SAFE_KEYWORDS_EN = {
    'sincerely': 3, 'regards': 3, 'best regards': 3, 'thank you': 1,
    'thanks': 1, 'meeting': 2, 'schedule': 2, 'appointment': 2,
    'calendar': 2, 'reply to': 1, 'discussion': 2, 'project': 2,
    'status update': 2, 'weekly': 1, 'daily': 1, 'monthly': 1,
    'report': 1, 'review': 1, 'feedback': 1, 'notes': 1,
    'internal': 2, 'team': 1, 'colleague': 2, 'employee': 1,
    'receipt': 2, 'order confirmation': 3, 'welcome': 1,
    'newsletter': 1, 'update from': 1, 'digest': 1,
    'news from': 1, 'unsubscribe': 2, 'preferences': 1
}

SPAM_KEYWORDS_AR = {
    'مجاني': 3, 'فوز': 4, 'رابح': 4, 'فزت': 4, 'جائزة': 5, 'مبروك': 3,
    'تهانينا': 3, 'عرض': 3, 'محدود': 2, 'حصري': 2, 'عاجل': 5,
    'الآن': 2, 'اليوم': 2, 'فقط': 2, 'مضمون': 4, '100%': 3,
    'اضغط هنا': 4, 'اشترِ الآن': 4, 'تحرك الآن': 4, 'خصم': 2, 'تخفيض': 2,
    'رخيص': 3, 'الأدنى سعر': 3, 'صفقة': 3, 'استثمار': 4, 'مليون': 4,
    'نقدي': 3, 'مال': 3, 'دخل': 4, 'ربح': 4, 'يانصيب': 5,
    'قرض': 3, 'ائتمان': 2, 'دين': 2, 'رهن': 3, 'تأمين': 2,
    'استرداد': 3, 'استبدال': 3, 'اشترك': 2,
    'تخسيس وزن': 4, 'رجيم': 3, 'مكملات': 4, 'ادوية': 4,
    'مواعدة': 2, 'عازب': 3, 'ساخن': 2, 'جنس': 5,
    'بنك': 2, 'باى بال': 3, 'تحقق': 5, 'تأكيد': 3, 'تحديث': 3,
    'حساب': 3, 'كلمة مرور': 3, 'تسجيل دخول': 3, 'أمن': 3,
    'صديقي العزيز': 4, 'عزيزي': 3, 'تحياتي': 2,
    'تحميل': 3, 'مرفق': 3, 'فاتورة': 3, 'كشف حساب': 3,
    'جهة حكومية': 3, 'شرطة': 3, 'محكمة': 4,
    'تحويل بنكي': 4, 'أرسل مالاً': 5,
    'بيتكوين': 3, 'عملة رقمية': 3, 'محفظة': 3,
    'برامج ضارة': 2, 'فيروس': 2, 'موقوف': 4, 'ملغى': 4
}

PHISHING_KEYWORDS_AR = {
    'تحقق من حسابك': 8, 'تأكيد هويتك': 8, 'حسابك موقوف': 8,
    'حسابك مخترق': 9, 'نشاط غير معتاد': 7, 'تنبيه أمني': 7,
    'يرجى التأكيد': 6, 'اضغط للتحقق': 8, 'سجل دخول للتأكيد': 8,
    'حدث بيانات الدفع': 7, 'فشل الدفع': 6, 'تم رفض الدفع': 6,
    'تحقق من الشراء': 7, 'سيتم إيقاف حسابك': 7, 'خلال 24 ساعة': 6,
    'إجراء فوري مطلوب': 8, 'عدم الامتثال': 7,
    'إعادة تعيين كلمة المرور': 5, 'انتهت صلاحية كلمة المرور': 6,
    'عميلنا العزيز': 5, 'مستخدمنا العزيز': 4, 'عميلنا المميز': 4,
    'هذا إشعار رسمي': 4, 'ممثل معتمد': 5,
    'لاحظنا تسجيل دخول': 7, 'محاولة تسجيل دخول جديدة': 7,
    'شخص ما لديه كلمة مرورك': 9, 'كلمة مرورك مسربة': 9,
    'معرف أبل': 6, 'حساب جوجل': 6, 'حساب مايكروسوفت': 6,
    'أمازون': 6, 'إي باي': 5, 'نتفليكس': 5, 'سبوتيفاي': 5,
    'طلبك': 5, 'فشل التوصيل': 5, 'شحن': 4,
    'http://': 4, 'رابط مختصر': 3,
    'افتح المرفق': 5, 'حمّل المستند': 5,
    'تفعيل الماكرو': 9, 'مكتب 365': 4, 'جوجل درايف': 5
}

URGENT_KEYWORDS_AR = {
    'عاجل جداً': 8, 'عاجل': 6, 'فوراً': 5, 'الآن': 3, 'اليوم': 2,
    'هذا الصباح': 3, 'هذه الليلة': 3, 'مباشرة': 5, 'حالاً': 5,
    '24 ساعة': 4, '48 ساعة': 3, 'موعد نهائي': 5, 'ينتهي': 4,
    'آخر فرصة': 5, 'إشعار نهائي': 6, 'تحذير نهائي': 6,
    'حرج': 5, 'طارئ': 6, 'مهم': 2, 'حساس الوقت': 5,
    'لا تفوت': 3, 'وقت محدود': 4,
    'تحرك الآن': 5, 'لا تتأخر': 5, 'بدون تأخير': 5,
    'حريق': 7, 'اختراق': 7, 'اخترق': 7, 'تسريب': 7,
    'ساعدني': 5, 'من فضلك ساعد': 4, 'عالق': 3, 'أحتاجك': 3,
    'هل يمكنك إرسال': 4, 'هل يمكنك شراء': 5, 'أحتاجك لـ': 4,
    'الرئيس التنفيذي': 5, 'المدير': 3, 'المدير العام': 3, 'الموارد البشرية': 3,
    'سري': 4, 'بيننا': 4, 'لا تشارك': 4,
    'طلب سريع': 5, 'أمر شخصي': 3
}

URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
LINK_TEXT_REGEX = re.compile(r'<a[^>]*href=["\'](.*?)["\'][^>]*>(.*?)</a>', re.DOTALL | re.IGNORECASE)


def _match_keywords(text, keyword_dict):
    text_lower = text.lower()
    score = 0.0
    hits = []
    for phrase, weight in keyword_dict.items():
        phrase_lower = phrase.lower()
        count = 0
        if len(phrase_lower.split()) > 1:
            count = text_lower.count(phrase_lower)
        else:
            count = len(re.findall(r'\b' + re.escape(phrase_lower) + r'\b', text_lower))
        if count > 0:
            score += weight * count
            hits.append({'keyword': phrase, 'count': count, 'weight': weight})
    return score, hits


def _analyze_headers(sender, subject, content_type):
    score = 0.0
    notes = []
    if sender:
        if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', sender):
            pass
        else:
            score += 10
            notes.append('Sender format looks suspicious')
        sender_lower = sender.lower()
        if 'noreply' in sender_lower or 'no-reply' in sender_lower:
            pass
        if any(s in sender_lower for s in ['verify', 'secure', 'support', 'service', 'help', 'admin']):
            if not any(d in sender_lower for d in ['.com', '.org', '.net', '.edu', '.gov']):
                score += 5
        if len(re.findall(r'\d', sender)) > 5 and '@' in sender:
            score += 5
            notes.append('Sender contains many numbers')
    if subject:
        if not subject or subject.strip() == '':
            score += 5
            notes.append('Empty subject')
        if len(subject) > 150:
            score += 2
        if any(ch in subject for ch in '!#$%&*'):
            score += min(subject.count(ch) for ch in '!#$%&*') * 2
        if subject.isupper():
            score += 5
            notes.append('Subject is all caps')
    if content_type:
        ct_lower = content_type.lower()
        if 'html' in ct_lower:
            score += 2
            notes.append('HTML email (slightly higher risk)')
    return score, notes


def _analyze_links(text):
    score = 0.0
    link_issues = []
    urls = URL_REGEX.findall(text)
    for url in urls:
        url_lower = url.lower()
        if url_lower.startswith('http://'):
            score += 3
            link_issues.append({'url': url[:150], 'issue': 'Non-HTTPS link'})
        if re.search(r'\d{1,3}(?:\.\d{1,3}){3}', url):
            score += 5
            link_issues.append({'url': url[:150], 'issue': 'IP address URL'})
        if any(s in url_lower for s in ['bit.ly', 'tinyurl', 't.co', 'is.gd', 'buff.ly', 'ow.ly']):
            score += 6
            link_issues.append({'url': url[:150], 'issue': 'Shortened URL (risk of hiding destination)'})
        if len(url) > 100:
            score += 2
        if '@' in url:
            score += 6
            link_issues.append({'url': url[:150], 'issue': 'URL contains @ (potential redirect)'})
    link_mismatches = LINK_TEXT_REGEX.findall(text)
    for href, display in link_mismatches:
        display_urls = URL_REGEX.findall(display)
        if display_urls and href not in display_urls[0]:
            score += 10
            link_issues.append({'display': display.strip()[:100], 'actual': href[:150],
                                'issue': 'Display text URL differs from actual href (classic phishing)'})
    return score, link_issues


def classify_email_ai(sender=None, subject=None, body=None):
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
        "You are an advanced cybersecurity email classification assistant. "
        "Analyze the provided email subject, sender, and body. "
        "Classify the email strictly into one of these four categories: 'Safe', 'Spam', 'Phishing', or 'Urgent'. "
        "Return a valid JSON object with keys: 'classification' (string), 'confidence_score' (float between 0 and 100), "
        "'risk_score' (float between 0 and 100), and 'reasoning' (string)."
    )
    
    user_content = f"Sender: {sender}\nSubject: {subject}\nBody: {body}"
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            res_json = response.json()
            content = res_json['choices'][0]['message']['content']
            return json.loads(content)
    except Exception as e:
        logger.error(f"AI Email Classification error: {str(e)}")
    return None


def classify_email(sender=None, subject=None, body=None, content_type='text/plain'):
    body = body or ''
    subject = subject or ''
    sender = sender or ''
    
    # Try AI classification first
    ai_result = classify_email_ai(sender=sender, subject=subject, body=body)
    if ai_result and 'classification' in ai_result:
        label = ai_result.get('classification', 'Safe')
        if label not in ['Safe', 'Spam', 'Phishing', 'Urgent']:
            label = 'Safe'
        risk_score = float(ai_result.get('risk_score', ai_result.get('confidence_score', 10.0)))
        if risk_score >= 70:
            level = 'critical'
        elif risk_score >= 40:
            level = 'high'
        elif risk_score >= 15:
            level = 'medium'
        else:
            level = 'low'
            
        return {
            'classification': label,
            'risk_score': risk_score,
            'risk_level': level,
            'ai_reasoning': ai_result.get('reasoning', ''),
            'category_scores': {
                'spam_score': risk_score if label == 'Spam' else 0.0,
                'phishing_score': risk_score if label == 'Phishing' else 0.0,
                'urgent_score': risk_score if label == 'Urgent' else 0.0,
                'safe_score': 100 - risk_score if label == 'Safe' else 0.0
            },
            'hits': {'spam_hits': [], 'phishing_hits': [], 'urgent_hits': [], 'safe_hits': []},
            'header_notes': [],
            'link_issues': [],
            'attachments_detected': 0,
            'text_length': len(body),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }

    # Fallback to original regex and keyword logic if AI is unavailable
    full_text = f"{subject}\n{body}"
    scores = {
        'spam_score': 0.0,
        'phishing_score': 0.0,
        'urgent_score': 0.0,
        'safe_score': 0.0
    }
    hits_collection = {
        'spam_hits': [],
        'phishing_hits': [],
        'urgent_hits': [],
        'safe_hits': []
    }

    s, h = _match_keywords(full_text, SPAM_KEYWORDS_EN)
    scores['spam_score'] += s
    hits_collection['spam_hits'].extend(h)
    s, h = _match_keywords(full_text, SPAM_KEYWORDS_AR)
    scores['spam_score'] += s
    hits_collection['spam_hits'].extend(h)

    s, h = _match_keywords(full_text, PHISHING_KEYWORDS_EN)
    scores['phishing_score'] += s
    hits_collection['phishing_hits'].extend(h)
    s, h = _match_keywords(full_text, PHISHING_KEYWORDS_AR)
    scores['phishing_score'] += s
    hits_collection['phishing_hits'].extend(h)

    s, h = _match_keywords(full_text, URGENT_KEYWORDS_EN)
    scores['urgent_score'] += s
    hits_collection['urgent_hits'].extend(h)
    s, h = _match_keywords(full_text, URGENT_KEYWORDS_AR)
    scores['urgent_score'] += s
    hits_collection['urgent_hits'].extend(h)

    s, h = _match_keywords(full_text, SAFE_KEYWORDS_EN)
    scores['safe_score'] += s
    hits_collection['safe_hits'].extend(h)

    header_score, header_notes = _analyze_headers(sender, subject, content_type)
    scores['phishing_score'] += header_score * 0.5
    scores['spam_score'] += header_score * 0.3

    link_score, link_issues = _analyze_links(body)
    scores['phishing_score'] += link_score
    scores['spam_score'] += link_score * 0.5

    body_len = len(body)
    if body_len < 20 and scores['safe_score'] < 5:
        scores['spam_score'] += 3
    attachment_count = len(re.findall(r'\.(pdf|doc|docx|xls|xlsx|zip|rar|exe|js|vbs)', body, re.IGNORECASE))
    scores['phishing_score'] += attachment_count * 3
    scores['spam_score'] += attachment_count * 2

    capped = {k: min(v, 100) for k, v in scores.items()}

    weighted = {
        'Safe': capped['safe_score'] * 1.2 - (capped['spam_score'] + capped['phishing_score']) * 0.4,
        'Spam': capped['spam_score'],
        'Phishing': capped['phishing_score'],
        'Urgent': capped['urgent_score'] - capped['phishing_score'] * 0.5
    }

    label = max(weighted, key=weighted.get)
    if weighted['Phishing'] >= 25 and weighted['Phishing'] >= weighted['Spam']:
        label = 'Phishing'
    elif weighted['Spam'] >= 25 and weighted['Spam'] > weighted['Urgent'] and weighted['Spam'] > weighted['Safe']:
        label = 'Spam'
    elif weighted['Urgent'] >= 20 and weighted['Phishing'] < 20 and weighted['Spam'] < 25:
        label = 'Urgent'
    elif weighted['Safe'] >= 10 and weighted['Spam'] < 20 and weighted['Phishing'] < 15:
        label = 'Safe'

    if label == 'Phishing':
        risk_score = min(round(capped['phishing_score'] + capped['urgent_score'] * 0.3, 2), 100)
    elif label == 'Spam':
        risk_score = min(round(capped['spam_score'] * 0.8, 2), 100)
    elif label == 'Urgent':
        risk_score = min(round(capped['urgent_score'] * 0.6 + capped['phishing_score'] * 0.2, 2), 100)
    else:
        risk_score = min(round(max(0, 10 - capped['safe_score'] * 0.5 + capped['spam_score'] * 0.1 + capped['phishing_score'] * 0.1), 2), 100)

    if risk_score >= 70:
        level = 'critical'
    elif risk_score >= 40:
        level = 'high'
    elif risk_score >= 15:
        level = 'medium'
    else:
        level = 'low'

    return {
        'classification': label,
        'risk_score': risk_score,
        'risk_level': level,
        'category_scores': capped,
        'hits': hits_collection,
        'header_notes': header_notes,
        'link_issues': link_issues,
        'attachments_detected': attachment_count,
        'text_length': body_len,
        'timestamp': datetime.datetime.utcnow().isoformat()
    }


@mailguard_bp.route('/classify', methods=['POST'])
def classify():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Request body is required (JSON)'}), 400
        sender = data.get('sender', data.get('from', ''))
        subject = data.get('subject', '')
        body = data.get('body', data.get('content', data.get('text', '')))
        content_type = data.get('content_type', 'text/plain')
        if not body and not subject:
            return jsonify({'error': 'At least "body" or "subject" must be provided'}), 400
        result = classify_email(sender=sender, subject=subject, body=body, content_type=content_type)
        user_id = getattr(request, 'current_user', None)
        user_id = user_id.id if user_id else None
        scan_id = save_scan_record(
            current_app._get_current_object(),
            user_id=user_id,
            module='mailguard',
            target=(sender or '')[:100] + ' | ' + (subject or '')[:80],
            risk_score=result['risk_score'],
            details=result,
            raw_input_size=len(body or '') + len(subject or '')
        )
        result['scan_id'] = scan_id
        if result['risk_score'] >= 40:
            save_alert_record(
                current_app._get_current_object(),
                user_id=user_id,
                source='mailguard',
                severity='high' if result['risk_score'] >= 70 else 'medium',
                title=f'{result["classification"]} email detected',
                message=f'Email from {sender[:100] if sender else "unknown"} with subject "{subject[:150]}" was classified as {result["classification"]} with risk score {result["risk_score"]}',
                alert_metadata={'scan_id': scan_id, 'classification': result['classification']}
            )
        logger.info(f"MailGuard classification: {result['classification']} (risk={result['risk_score']})")
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"MailGuard classify error: {str(e)}")
        return jsonify({'error': f'Classification failed: {str(e)[:200]}'}), 500


@mailguard_bp.route('/batch', methods=['POST'])
def classify_batch():
    try:
        data = request.get_json(silent=True)
        if not data or 'emails' not in data or not isinstance(data['emails'], list):
            return jsonify({'error': 'Request body must include "emails" list'}), 400
        if len(data['emails']) > 100:
            return jsonify({'error': 'Batch size cannot exceed 100 emails'}), 400
        results = []
        user_id = getattr(request, 'current_user', None)
        user_id = user_id.id if user_id else None
        for idx, email in enumerate(data['emails']):
            try:
                r = classify_email(
                    sender=email.get('sender', email.get('from', '')),
                    subject=email.get('subject', ''),
                    body=email.get('body', email.get('content', email.get('text', ''))),
                    content_type=email.get('content_type', 'text/plain')
                )
                r['email_index'] = idx
                results.append(r)
            except Exception as inner_e:
                results.append({'email_index': idx, 'error': str(inner_e)[:200]})
        summary = Counter(r.get('classification', 'Error') for r in results)
        logger.info(f"MailGuard batch: {len(results)} emails processed. Summary: {dict(summary)}")
        return jsonify({
            'total': len(results),
            'summary': dict(summary),
            'results': results
        }), 200
    except Exception as e:
        logger.error(f"MailGuard batch error: {str(e)}")
        return jsonify({'error': f'Batch classification failed: {str(e)[:200]}'}), 500