/* SENTINEL-AI dashboard + landing SPA behaviors */
(function () {
  'use strict';

  const API_BASE = ''; // same-origin Flask
  const LANG_KEY = 'sentinel.lang';
  const TOKEN_KEY = 'sentinel.token';
  const USER_KEY = 'sentinel.user';

  const I18N = {
    en: {
      tagline: 'Secure Intelligence Platform',
      hero_title: 'One AI platform. Every security surface.',
      hero_sub: 'Scan PDFs for threats, classify emails, monitor servers, detect motion on cameras, and audit code and logs — from a single unified dashboard.',
      go_dashboard: 'Go to Dashboard',
      explore_modules: 'Explore Modules',
      modules: 'Modules',
      auth: 'Auth',
      db: 'Database',
      modules_title: 'Six integrated security modules',
      modules_sub: 'Each module has a dedicated REST API, database logging, and dashboard visualization.',
      m_doc_title: 'DocGuard', m_doc_desc: 'PDF & document scanner — suspicious URLs, credit cards (Luhn), dangerous keywords (AR/EN).',
      m_mail_title: 'MailGuard', m_mail_desc: 'Email classifier: Safe / Spam / Phishing / Urgent using keyword weighting + regex.',
      m_sys_title: 'SysGuard', m_sys_desc: 'Real-time CPU, RAM, Disk, Network monitoring with z-score anomaly detection.',
      m_cam_title: 'CamGuard', m_cam_desc: 'Motion detection via OpenCV; pluggable YOLOv8 object detection (TODO: weights required).',
      m_scan_title: 'ScanGuard', m_scan_desc: 'Static analysis for code & logs — SQLi, XSS, hardcoded secrets, risky functions.',
      m_auth_title: 'Auth Module', m_auth_desc: 'JWT access tokens, bcrypt password hashing, registration, login, admin listing.',
      cta_title: 'Ready to secure everything?',
      cta_sub: 'Open the dashboard, create an account, and start scanning in under 60 seconds.',
      launch: 'Launch Dashboard →',
      copyright: '© 2026 — Production-ready security platform',

      /* dashboard */
      control_center: 'Control Center',
      nav_overview: 'Overview',
      nav_doc: 'DocGuard',
      nav_mail: 'MailGuard',
      nav_sys: 'SysGuard',
      nav_cam: 'CamGuard',
      nav_scan: 'ScanGuard',
      nav_alerts: 'Alerts',
      nav_history: 'History',
      signed_out: 'Signed out',
      signed_in_as: 'Signed in as',
      title_overview: 'Overview',
      refresh: '↻ Refresh',
      logout: 'Sign out',

      auth_welcome: 'Welcome back',
      auth_sub: 'Sign in to enable scan history & alerts. Continue as guest if you prefer.',
      tab_login: 'Sign in',
      tab_register: 'Register',
      f_username: 'Username or email',
      f_email: 'Email',
      f_password: 'Password',
      f_first: 'First name',
      f_last: 'Last name',
      btn_login: 'Sign in',
      btn_register: 'Create account',
      btn_guest: 'Continue as guest',

      username_placeholder: 'you@example.com or username',
      email_placeholder: 'you@example.com',
      password_placeholder: 'At least 8 chars, mixed case + digit',
      optional: 'Optional',

      st_scans_24: 'Scans (24h)',
      st_critical: 'Critical scans',
      st_high: 'High-risk scans',
      st_unread: 'Unread alerts',
      st_today: 'Today',
      st_risk: 'Risk ≥ 70',
      st_risk2: 'Risk ≥ 40',
      st_action: 'Action needed',
      h_per_module: 'Per-module performance',
      h_sys_mini: 'System snapshot',
      btn_check: 'Check now',
      empty_click: 'Click ↻ Refresh to load dashboard summary.',
      empty_sys: 'Run SysGuard to view live CPU / RAM / Disk / Network.',
      empty_click_sys: 'Click "Check once" to load current status.',
      h_recent_scans: 'Recent scans',
      h_recent_alerts: 'Recent alerts',

      dg_title: 'DocGuard — Document Scanner',
      dg_upload: 'Upload PDF / TXT',
      dg_text: '…or paste raw text',
      dg_text_ph: 'Paste document text to scan for URLs, cards, and dangerous keywords…',
      btn_scan: '🔍 Scan Document',
      dg_result: 'Scan Result',

      mg_title: 'MailGuard — Email Classifier',
      mg_from: 'From / Sender',
      mg_from_ph: 'e.g. spoofed@paypal-support.xyz',
      mg_subject: 'Subject',
      mg_subject_ph: 'URGENT: Verify your account before it is closed',
      mg_body: 'Body',
      mg_body_ph: 'Paste the email body here…',
      btn_classify: '🎯 Classify Email',
      mg_result: 'Classification',

      sg_title: 'SysGuard — Real-time System Monitor',
      sg_once: '⟳ Check once',
      sg_start: '▶ Auto (5s)',
      sg_stop: '⏸ Stop auto',
      sg_hist: 'History (last 60 samples)',

      cg_title: 'CamGuard — Camera / Frame Analyzer',
      cg_frame: 'Upload frame image',
      cg_cam: 'Camera ID',
      cg_base64: '…or paste base64 (data URI ok)',
      cg_b64_ph: 'data:image/png;base64, ....',
      cg_yolo: 'Attempt YOLO (placeholder — install ultralytics + weights)',
      btn_analyze: '📷 Analyze Frame',
      cg_todo: 'TODO YOLO: pip install ultralytics + drop yolov8*.pt in project root. Motion detection works out of the box.',
      cg_result: 'Frame analysis',

      sg2_title: 'ScanGuard — Code / Log Scanner',
      sg2_upload: 'Upload file (code / log / txt)',
      sg2_type: 'Hint type',
      sg2_auto: 'Auto detect',
      sg2_code: 'Code',
      sg2_log: 'Log file',
      sg2_text: '…or paste code / log text',
      sg2_text_ph: 'Paste source code or log output to scan for SQLi/XSS/secrets…',
      btn_audit: '🛡️ Audit',
      sg2_result: 'Audit report',

      al_title: 'Alerts',
      al_all: 'All severities',
      al_unread: 'Unread only',

      hist_title: 'Scan history',
      hist_all: 'All modules',

      col_module: 'Module', col_target: 'Target', col_risk: 'Risk', col_level: 'Level',
      col_time: 'Created', col_id: 'ID', col_action: 'Action',
      col_severity: 'Severity', col_source: 'Source', col_title: 'Title', col_msg: 'Message',
      read: 'Mark read',
      no_data: '— No data yet —',

      critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', safe: 'Safe',
      spam: 'Spam', phishing: 'Phishing', urgent: 'Urgent',
      saved_scan: 'Scan saved to history',
      alert_created: 'Alert raised',
      login_ok: 'Signed in successfully',
      register_ok: 'Account created successfully',
      logout_ok: 'Signed out',
      mark_read_ok: 'Alert marked read'
    },
    ar: {
      tagline: 'منصة ذكاء أمني',
      hero_title: 'منصة ذكاء واحدة. كل وجهات الأمان.',
      hero_sub: 'افحص ملفات PDF، صنّف الإيميلات، راقب الخوادم، اكتشف الحركة على الكاميرات، وتدقيق الأكواد واللوجات — كل ذلك من لوحة تحكم موحدة.',
      go_dashboard: 'اذهب للوحة التحكم',
      explore_modules: 'استكشف الموديولات',
      modules: 'موديولات',
      auth: 'مصادقة',
      db: 'قاعدة بيانات',
      modules_title: 'ستة موديولات أمني متكاملة',
      modules_sub: 'كل موديول يتوفر على REST API مخصص، تسجيل في قاعدة البيانات، ورسم بياني على اللوحة.',
      m_doc_title: 'DocGuard', m_doc_desc: 'ماسح مستندات PDF — روابط مشبوهة، بطاقات ائتمان (Luhn)، كلمات مفتاحية خطرة (عربي/إنجليزي).',
      m_mail_title: 'MailGuard', m_mail_desc: 'تصنيف الإيميلات: آمن / سبام / تصيّد / عاجل عبر ترجيح كلمات + regex.',
      m_sys_title: 'SysGuard', m_sys_desc: 'مراقبة مباشرة للمعالج والذاكرة والقرص والشبكة مع كشف شذوذ عبر z-score.',
      m_cam_title: 'CamGuard', m_cam_desc: 'كشف حركة بـ OpenCV؛ مع توصيلة جاهزة لـ YOLOv8 (TODO: تحتاج أوزان).',
      m_scan_title: 'ScanGuard', m_scan_desc: 'تحليل ثابت للأكواد واللوجات — SQLi، XSS، أسرار مُضمّنة، دوال خطرة.',
      m_auth_title: 'موديول المصادقة', m_auth_desc: 'رموز JWT، تشفير كلمات السر بـ bcrypt، تسجيل، دخول، قائمة مشرفين.',
      cta_title: 'جاهز لتأمين كل شيء؟',
      cta_sub: 'افتح اللوحة، أنشئ حساباً، وابدأ الفحص في أقل من 60 ثانية.',
      launch: 'إطلاق اللوحة ←',
      copyright: '© 2026 — منصة أمن جاهزة للإنتاج',

      control_center: 'مركز التحكم',
      nav_overview: 'نظرة عامة',
      nav_doc: 'DocGuard',
      nav_mail: 'MailGuard',
      nav_sys: 'SysGuard',
      nav_cam: 'CamGuard',
      nav_scan: 'ScanGuard',
      nav_alerts: 'التنبيهات',
      nav_history: 'السجل',
      signed_out: 'تم تسجيل الخروج',
      signed_in_as: 'مسجل باسم',
      title_overview: 'نظرة عامة',
      refresh: '↻ تحديث',
      logout: 'خروج',

      auth_welcome: 'أهلاً بعودتك',
      auth_sub: 'سجل دخول لتفعيل سجل عمليات الفحص والتنبيهات. أو تابع كضيف إن أردت.',
      tab_login: 'دخول',
      tab_register: 'حساب جديد',
      f_username: 'اسم المستخدم أو البريد',
      f_email: 'البريد الإلكتروني',
      f_password: 'كلمة المرور',
      f_first: 'الاسم الأول',
      f_last: 'اسم العائلة',
      btn_login: 'تسجيل الدخول',
      btn_register: 'إنشاء الحساب',
      btn_guest: 'المتابعة كضيف',

      username_placeholder: 'you@example.com أو اسم مستخدم',
      email_placeholder: 'you@example.com',
      password_placeholder: 'لا تقل عن 8 أحرف، كبيرة وصغيرة + رقم',
      optional: 'اختياري',

      st_scans_24: 'الفحوصات (24 ساعة)',
      st_critical: 'فحوصات حرجة',
      st_high: 'فحوصات عالية الخطورة',
      st_unread: 'تنبيهات غير مقروءة',
      st_today: 'اليوم',
      st_risk: 'خطورة ≥ 70',
      st_risk2: 'خطورة ≥ 40',
      st_action: 'تتطلب إجراءً',
      h_per_module: 'أداء كل موديول',
      h_sys_mini: 'لقاء للنظام',
      btn_check: 'افحص الآن',
      empty_click: 'اضغط ↻ تحديث لتحميل ملخص اللوحة.',
      empty_sys: 'شغّل SysGuard لعرض المعالج / الذاكرة / القرص / الشبكة.',
      empty_click_sys: 'اضغط "افحص الآن" لعرض الحالة الحالية.',
      h_recent_scans: 'آخر الفحوصات',
      h_recent_alerts: 'آخر التنبيهات',

      dg_title: 'DocGuard — ماسح المستندات',
      dg_upload: 'ارفع PDF / TXT',
      dg_text: '…أو الصق نصّاً مباشرة',
      dg_text_ph: 'الصق نص المستند لفحص الروابط والبطاقات والكلمات الخطرة…',
      btn_scan: '🔍 فحص المستند',
      dg_result: 'نتيجة الفحص',

      mg_title: 'MailGuard — مصنف الإيميلات',
      mg_from: 'المرسل / Sender',
      mg_from_ph: 'مثال: spoofed@paypal-support.xyz',
      mg_subject: 'الموضوع',
      mg_subject_ph: 'عاجل جداً: تحقق من حسابك قبل إغلاقه',
      mg_body: 'المحتوى',
      mg_body_ph: 'الصق هنا نص الإيميل…',
      btn_classify: '🎯 تصنيف الإيميل',
      mg_result: 'التصنيف',

      sg_title: 'SysGuard — مراقبة النظام مباشرة',
      sg_once: '⟳ فحص لمرة واحدة',
      sg_start: '▶ تلقائي (5 ثوانٍ)',
      sg_stop: '⏸ إيقاف التلقائي',
      sg_hist: 'التاريخ (آخر 60 عينة)',

      cg_title: 'CamGuard — محلّل لقطات الكاميرا',
      cg_frame: 'ارفع صورة الإطار',
      cg_cam: 'معرّف الكاميرا',
      cg_base64: '…أو الصق base64 (data URI مقبول)',
      cg_b64_ph: 'data:image/png;base64, ....',
      cg_yolo: 'محاولة YOLO (بصيغة placeholder — ثبّت ultralytics + أوزان)',
      btn_analyze: '📷 تحليل الإطار',
      cg_todo: 'TODO YOLO: pip install ultralytics + ضع yolov8*.pt في مجلد المشروع. كشف الحركة يعمل مباشرة.',
      cg_result: 'تحليل الإطار',

      sg2_title: 'ScanGuard — ماسح الأكواد واللوجات',
      sg2_upload: 'ارفع ملف (كود / لوج / نص)',
      sg2_type: 'نوع التلميح',
      sg2_auto: 'اكتشاف تلقائي',
      sg2_code: 'كود',
      sg2_log: 'ملف لوج',
      sg2_text: '…أو الصق النص هنا',
      sg2_text_ph: 'الصق كود مصدر أو لوج للبحث عن SQLi/XSS/أسرار…',
      btn_audit: '🛡️ تدقيق',
      sg2_result: 'تقرير التدقيق',

      al_title: 'التنبيهات',
      al_all: 'كل الشدات',
      al_unread: 'غير المقروءة فقط',

      hist_title: 'سجل الفحوصات',
      hist_all: 'كل الموديولات',

      col_module: 'الموديول', col_target: 'المستهدف', col_risk: 'الخطورة', col_level: 'المستوى',
      col_time: 'الوقت', col_id: 'الرقم', col_action: 'إجراء',
      col_severity: 'الشدة', col_source: 'المصدر', col_title: 'العنوان', col_msg: 'الرسالة',
      read: 'تحديد كمقروء',
      no_data: '— لا توجد بيانات حتى الآن —',

      critical: 'حرج', high: 'عالي', medium: 'متوسط', low: 'منخفض', safe: 'آمن',
      spam: 'سبام', phishing: 'تصيّد', urgent: 'عاجل',
      saved_scan: 'تم حفظ الفحص في السجل',
      alert_created: 'تم إصدار تنبيه',
      login_ok: 'تم تسجيل الدخول بنجاح',
      register_ok: 'تم إنشاء الحساب بنجاح',
      logout_ok: 'تم تسجيل الخروج',
      mark_read_ok: 'تم تحديد التنبيه كمقروء'
    }
  };

  let state = {
    lang: localStorage.getItem(LANG_KEY) || (navigator.language && navigator.language.toLowerCase().startsWith('ar') ? 'ar' : 'en'),
    token: localStorage.getItem(TOKEN_KEY) || null,
    user: null,
    authMode: 'login',
    streamTimer: null,
    currentView: 'overview'
  };
  try { state.user = JSON.parse(localStorage.getItem(USER_KEY) || 'null'); } catch(_) { state.user = null; }

  function t(key) {
    return (I18N[state.lang] || I18N.en)[key] || (I18N.en[key] || key);
  }

  function applyI18n() {
    document.documentElement.lang = state.lang;
    document.documentElement.dir = state.lang === 'ar' ? 'rtl' : 'ltr';
    document.querySelectorAll('[data-i18n]').forEach(el => {
      el.textContent = t(el.getAttribute('data-i18n'));
    });
    document.querySelectorAll('[data-placeholder]').forEach(el => {
      el.setAttribute('placeholder', t(el.getAttribute('data-placeholder')));
    });
    const btns = { btn_en: document.getElementById('btn-en'), btn_ar: document.getElementById('btn-ar') };
    if (btns.btn_en) btns.btn_en.setAttribute('aria-pressed', String(state.lang === 'en'));
    if (btns.btn_ar) btns.btn_ar.setAttribute('aria-pressed', String(state.lang === 'ar'));
  }

  function bindLangSwitches() {
    ['btn-en', 'btn-ar'].forEach(id => {
      const btn = document.getElementById(id);
      if (!btn) return;
      btn.addEventListener('click', () => {
        state.lang = id === 'btn-en' ? 'en' : 'ar';
        localStorage.setItem(LANG_KEY, state.lang);
        applyI18n();
      });
    });
  }

  function toast(msg, kind) {
    const area = document.getElementById('toastArea');
    if (!area) return;
    const el = document.createElement('div');
    el.className = 'toast ' + (kind === 'err' ? 'err' : 'ok');
    el.textContent = msg;
    area.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateY(6px)'; el.style.transition = 'all .25s'; }, 3200);
    setTimeout(() => el.remove(), 3800);
  }

  async function api(method, path, body, opts) {
    opts = opts || {};
    const headers = { 'Accept': 'application/json' };
    if (!(body instanceof FormData)) headers['Content-Type'] = 'application/json';
    if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
    const init = {
      method: method,
      headers: headers,
      credentials: 'include'
    };
    if (body !== undefined && body !== null) {
      init.body = (body instanceof FormData) ? body : JSON.stringify(body);
    }
    try {
      const res = await fetch(API_BASE + path, init);
      const text = await res.text();
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch (_) { data = { raw: text }; }
      if (!res.ok && !opts.silent) {
        const msg = (data && (data.error || data.message)) || ('HTTP ' + res.status);
        toast(msg, 'err');
      }
      return { ok: res.ok, status: res.status, data: data };
    } catch (e) {
      if (!opts.silent) toast(String(e), 'err');
      return { ok: false, status: 0, data: null, error: e };
    }
  }

  function levelClass(val, isClassification) {
    if (isClassification) {
      if (typeof val === 'string') {
        const k = val.toLowerCase();
        if (k === 'safe') return 'pill-safe';
        if (k === 'spam') return 'pill-spam';
        if (k === 'phishing') return 'pill-phishing';
        if (k === 'urgent') return 'pill-urgent';
      }
      return 'pill-medium';
    }
    const n = typeof val === 'number' ? val : (typeof val === 'string' ? parseFloat(val) || 0 : 0);
    if (n >= 70) return 'pill-critical';
    if (n >= 40) return 'pill-high';
    if (n >= 15) return 'pill-medium';
    return 'pill-low';
  }
  function levelLabel(level) {
    const k = String(level || '').toLowerCase();
    return t({critical:'critical', high:'high', medium:'medium', low:'low', safe:'safe',
              spam:'spam', phishing:'phishing', urgent:'urgent'}[k] || k);
  }

  function riskChip(el, score, level) {
    if (!el) return;
    el.textContent = (level ? (levelLabel(level).toUpperCase ? levelLabel(level).toUpperCase() : levelLabel(level)) : '') +
      '  ' + (typeof score === 'number' ? score.toFixed(0) : score);
    el.classList.remove('risk-critical', 'risk-high', 'risk-medium', 'risk-low');
    el.classList.add('risk-' + (['critical','high','medium','low'].includes(level) ? level : 'low'));
  }

  function jsonBlockHTML(obj) {
    return '<div class="json-block">' + escapeHtml(JSON.stringify(obj, null, 2)) + '</div>';
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  function fmtDateTime(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString(state.lang === 'ar' ? 'ar-EG' : undefined); }
    catch(_) { return String(iso); }
  }

  function updateAuthUI() {
    const dot = document.getElementById('authDot');
    const lbl = document.getElementById('authLabel');
    const gate = document.getElementById('authGate');
    const content = document.getElementById('dashboardContent');
    const logout = document.getElementById('logoutBtn');
    const guest = document.getElementById('guestBtn');
    const statusEls = document.querySelectorAll('.auth-only');
    if (state.token) {
      if (dot) { dot.classList.add('on'); dot.classList.remove('off'); }
      if (lbl) lbl.textContent = t('signed_in_as') + ' ' + (state.user ? state.user.username : '…');
      if (gate) gate.classList.add('hidden');
      if (content) content.classList.remove('hidden');
      if (logout) logout.classList.remove('hidden');
    } else if (guest && guest.dataset.guestActive === '1') {
      if (dot) { dot.classList.add('on'); dot.classList.remove('off'); dot.style.background = '#06b6d4'; }
      if (lbl) lbl.textContent = 'Guest';
      if (gate) gate.classList.add('hidden');
      if (content) content.classList.remove('hidden');
    } else {
      if (dot) { dot.classList.remove('on'); dot.classList.add('off'); }
      if (lbl) lbl.textContent = t('signed_out');
      if (gate) gate.classList.remove('hidden');
      if (content) content.classList.add('hidden');
      if (logout) logout.classList.add('hidden');
    }
    // Toggle auth-only elements
    statusEls.forEach(el => {
      if (el.classList.contains('hidden-flag')) return;
      if (state.token) el.classList.remove('hidden');
      else el.classList.add('hidden');
    });
  }

  function bindAuth() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(x => x.classList.remove('active'));
        tab.classList.add('active');
        state.authMode = tab.dataset.tab;
        const regOnly = document.querySelectorAll('.register-only');
        const submit = document.getElementById('authSubmitBtn');
        regOnly.forEach(el => el.classList.toggle('hidden', state.authMode !== 'register'));
        if (submit) submit.textContent = state.authMode === 'register' ? t('btn_register') : t('btn_login');
      });
    });
    const form = document.getElementById('authForm');
    if (form) {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const errEl = document.getElementById('authError');
        if (errEl) errEl.textContent = '';
        const fd = new FormData(form);
        const body = Object.fromEntries(fd.entries());
        const isReg = state.authMode === 'register';
        let res;
        if (isReg) {
          const payload = {
            username: body.identifier, email: body.email, password: body.password,
            first_name: body.first_name, last_name: body.last_name
          };
          res = await api('POST', '/api/auth/register', payload, {silent: true});
        } else {
          const payload = { username: body.identifier, password: body.password, email: body.identifier };
          res = await api('POST', '/api/auth/login', payload, {silent: true});
        }
        if (!res.ok) {
          if (errEl) {
            if (res.data && res.data.details && Array.isArray(res.data.details)) {
              errEl.textContent = res.data.error + ': ' + res.data.details.join(' | ');
            } else {
              errEl.textContent = (res.data && (res.data.error || res.data.message)) || 'Auth failed';
            }
          }
          return;
        }
        state.token = res.data.token;
        state.user = res.data.user || null;
        localStorage.setItem(TOKEN_KEY, state.token);
        localStorage.setItem(USER_KEY, JSON.stringify(state.user || null));
        toast(isReg ? t('register_ok') : t('login_ok'));
        updateAuthUI();
        refreshDashboardSummary();
      });
    }
    const guest = document.getElementById('guestBtn');
    if (guest) {
      guest.addEventListener('click', () => {
        guest.dataset.guestActive = '1';
        updateAuthUI();
      });
    }
    const logout = document.getElementById('logoutBtn');
    if (logout) {
      logout.addEventListener('click', () => {
        state.token = null; state.user = null;
        localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY);
        const g = document.getElementById('guestBtn'); if (g) g.dataset.guestActive = '0';
        toast(t('logout_ok')); updateAuthUI();
      });
    }
  }

  function bindNav() {
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        document.querySelectorAll('.nav-link').forEach(x => x.classList.remove('active'));
        link.classList.add('active');
        const name = link.dataset.nav;
        state.currentView = name;
        document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
        const v = document.getElementById('view-' + name);
        if (v) v.classList.remove('hidden');
        const title = document.querySelector('.page-title');
        if (title) title.textContent = t('nav_' + name);
        // mobile sidebar close
        document.getElementById('sidebar')?.classList.remove('open');
        // auto-loads
        if (name === 'overview') refreshDashboardSummary();
        if (name === 'alerts') loadAlerts();
        if (name === 'history') loadScanHistory();
        if (name === 'sysguard') loadSysguardHistory();
      });
    });
    const toggle = document.getElementById('toggleSidebar');
    if (toggle) toggle.addEventListener('click', () => document.getElementById('sidebar').classList.toggle('open'));
    const refresh = document.getElementById('refreshBtn');
    if (refresh) refresh.addEventListener('click', refreshDashboardSummary);
    const sysQuick = document.querySelector('[data-action="sysguard-quick"]');
    if (sysQuick) sysQuick.addEventListener('click', runSysguardOnce);
  }

  /* ========== Overview ========== */
  async function refreshDashboardSummary() {
    // Load counts first (non auth)
    document.getElementById('st-scans-24').textContent = '…';
    document.getElementById('st-critical').textContent = '…';
    document.getElementById('st-high').textContent = '…';
    document.getElementById('st-unread').textContent = '…';

    const [sumRes, alertsRes] = await Promise.all([
      api('GET', '/api/dashboard/summary', undefined, {silent: true}),
      api('GET', '/api/alerts?per_page=1', undefined, {silent: true})
    ]);
    if (sumRes.ok && sumRes.data) {
      const s = sumRes.data;
      document.getElementById('st-scans-24').textContent = s.scans ? (s.scans.last_24h ?? 0) : 0;
      document.getElementById('st-critical').textContent = s.scans ? (s.scans.critical ?? 0) : 0;
      document.getElementById('st-high').textContent = s.scans ? (s.scans.high_risk ?? 0) : 0;
      const un = (alertsRes.ok && alertsRes.data) ? (alertsRes.data.unread_count ?? 0) : 0;
      document.getElementById('st-unread').textContent = un;
      const badge = document.getElementById('alertsBadge');
      if (badge) badge.style.display = un > 0 ? 'inline-block' : 'none';

      // module bars
      const mb = document.getElementById('moduleBars');
      if (mb) {
        if (!s.by_module || !s.by_module.length) {
          mb.innerHTML = '<p class="empty">' + t('no_data') + '</p>';
        } else {
          mb.innerHTML = s.by_module.map(m => {
            const pct = Math.min(100, Math.max(1, m.max_risk || 1));
            return `<div class="bar-row">
              <div class="name">${escapeHtml(m.module)}</div>
              <div class="bar"><span style="width:${pct}%"></span></div>
              <div class="v">${m.avg_risk ?? 0}</div>
              <div class="max">${t('col_risk')} max ${m.max_risk ?? 0}</div>
            </div>`;
          }).join('') + `<div style="margin-top:14px"></div>`;
          // append scan count under bars
          const kv = s.by_module.map(m => `<div><span>${escapeHtml(m.module)} — ${t('no_data')}</span><span>${m.scan_count} scans</span></div>`).join('');
          mb.insertAdjacentHTML('beforeend', `<div class="kv">${kv}</div>`);
        }
      }

      // recent tables
      renderScanTable(document.getElementById('recentScansTbl'), (s.recent_scans || []), 10);
      renderAlertTable(document.getElementById('recentAlertsTbl'), (s.recent_alerts || []), 8, false);
    }
  }

  function renderScanTable(table, rows, limit) {
    if (!table) return;
    rows = Array.isArray(rows) ? rows.slice(0, limit || 10) : [];
    table.innerHTML = `
      <thead><tr>
        <th>${t('col_module')}</th>
        <th>${t('col_target')}</th>
        <th>${t('col_risk')}</th>
        <th>${t('col_level')}</th>
        <th>${t('col_time')}</th>
      </tr></thead>
      <tbody>
        ${!rows.length ? `<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text-dimmer)">${t('no_data')}</td></tr>` :
          rows.map(r => `<tr>
            <td><code style="color:var(--accent)">${escapeHtml(r.module || '')}</code></td>
            <td>${escapeHtml(String(r.target || '').slice(0, 60))}</td>
            <td><strong>${Number(r.risk_score || 0).toFixed(0)}</strong></td>
            <td><span class="pill ${levelClass(r.risk_score || 0)}">${levelLabel(r.risk_level)}</span></td>
            <td style="color:var(--text-dim);font-size:12px">${fmtDateTime(r.created_at)}</td>
          </tr>`).join('')}
      </tbody>`;
  }
  function renderAlertTable(table, rows, limit, withAction) {
    if (!table) return;
    rows = Array.isArray(rows) ? rows.slice(0, limit || 10) : [];
    table.innerHTML = `
      <thead><tr>
        <th>${t('col_severity')}</th>
        <th>${t('col_source')}</th>
        <th>${t('col_title')}</th>
        <th>${t('col_msg')}</th>
        <th>${t('col_time')}</th>
        ${withAction ? `<th>${t('col_action')}</th>` : ''}
      </tr></thead>
      <tbody>
        ${!rows.length ? `<tr><td colspan="${withAction ? 6 : 5}" style="text-align:center;padding:20px;color:var(--text-dimmer)">${t('no_data')}</td></tr>` :
          rows.map(a => `<tr>
            <td><span class="pill pill-${(a.severity||'info').toLowerCase()}">${levelLabel(a.severity || 'info')}</span></td>
            <td><code style="color:var(--accent)">${escapeHtml(a.source || '')}</code></td>
            <td>${escapeHtml(String(a.title || '').slice(0, 90))}</td>
            <td style="color:var(--text-dim);font-size:12px">${escapeHtml(String(a.message || '').slice(0, 120))}</td>
            <td style="color:var(--text-dim);font-size:12px">${fmtDateTime(a.created_at)}</td>
            ${withAction ? `<td>${!a.is_read ? `<button class="btn-link" data-mark-read="${a.id}">${t('read')}</button>` : '<span style="color:var(--text-dimmer)">✓</span>'}</td>` : ''}
          </tr>`).join('')}
      </tbody>`;
    if (withAction) {
      table.querySelectorAll('[data-mark-read]').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.getAttribute('data-mark-read');
          const r = await api('POST', '/api/alerts/' + id + '/read');
          if (r.ok) { toast(t('mark_read_ok')); loadAlerts(); refreshDashboardSummary(); }
        });
      });
    }
  }

  /* ========== DocGuard ========== */
  function bindDocguard() {
    const form = document.getElementById('docguardForm');
    if (!form) return;
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = document.getElementById('dgError'); if (errEl) errEl.textContent = '';
      const fd = new FormData(form);
      const hasFile = fd.get('file') && fd.get('file').size > 0;
      const hasText = (fd.get('text') || '').toString().trim().length > 0;
      if (!hasFile && !hasText) { if (errEl) errEl.textContent = 'Provide a file or text.'; return; }
      let res;
      if (hasFile) {
        const body = new FormData();
        body.append('file', fd.get('file'));
        res = await api('POST', '/api/docguard/scan', body);
      } else {
        res = await api('POST', '/api/docguard/scan', { text: fd.get('text').toString(), filename: 'pasted_text.txt' });
      }
      if (res.ok && res.data) {
        const r = res.data;
        riskChip(document.getElementById('dgRiskChip'), r.risk_score, r.risk_level);
        const card = document.getElementById('dgResultCard'); if (card) card.style.display = '';
        const html = `
          <div class="kv">
            <div><span>File</span><span>${escapeHtml(r.filename || '—')}</span></div>
            <div><span>Text length</span><span>${r.text_length ?? 0}</span></div>
            <div><span>Issues found</span><span>${r.issues_found ?? 0}</span></div>
          </div>
          <h4 style="margin:16px 0 6px">Issues</h4>
          ${jsonBlockHTML(r.issues || {})}
          ${r.extraction_warnings && r.extraction_warnings.length ?
            `<p style="margin-top:12px;color:var(--text-dim)">Warnings: ${escapeHtml(r.extraction_warnings.join(' | '))}</p>` : ''}
        `;
        const box = document.getElementById('dgResult'); if (box) box.innerHTML = html;
        toast(t('saved_scan'));
      }
    });
  }

  /* ========== MailGuard ========== */
  function bindMailguard() {
    const form = document.getElementById('mailguardForm');
    if (!form) return;
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = document.getElementById('mgError'); if (errEl) errEl.textContent = '';
      const fd = new FormData(form);
      const res = await api('POST', '/api/mailguard/classify', {
        sender: fd.get('sender')?.toString(),
        subject: fd.get('subject')?.toString(),
        body: (fd.get('body') || '').toString(),
        content_type: 'text/plain'
      });
      if (res.ok && res.data) {
        const r = res.data;
        riskChip(document.getElementById('mgRiskChip'), r.risk_score, r.classification);
        const chip = document.getElementById('mgRiskChip');
        if (chip) chip.setAttribute('data-level', r.classification);
        document.getElementById('mgResultCard').style.display = '';
        const cat = r.category_scores || {};
        const html = `
          <div class="kv">
            <div><span>Classification</span><span><span class="pill ${levelClass(r.classification, true)}">${levelLabel(r.classification)}</span></span></div>
            <div><span>Risk score</span><span>${r.risk_score ?? 0}</span></div>
            <div><span>Attachments detected</span><span>${r.attachments_detected ?? 0}</span></div>
          </div>
          <h4 style="margin:14px 0 6px">Category scores</h4>
          <div class="kv">
            <div><span>Safe</span><span>${Number(cat.safe_score||0).toFixed(1)}</span></div>
            <div><span>Spam</span><span>${Number(cat.spam_score||0).toFixed(1)}</span></div>
            <div><span>Phishing</span><span>${Number(cat.phishing_score||0).toFixed(1)}</span></div>
            <div><span>Urgent</span><span>${Number(cat.urgent_score||0).toFixed(1)}</span></div>
          </div>
          ${(r.link_issues && r.link_issues.length) || (r.header_notes && r.header_notes.length) ? `
            <h4 style="margin:14px 0 6px">Notes</h4>
            ${jsonBlockHTML({header_notes: r.header_notes || [], link_issues: r.link_issues || []})}
          ` : ''}
          <h4 style="margin:14px 0 6px">Keyword hits</h4>
          ${jsonBlockHTML(r.hits || {})}
        `;
        document.getElementById('mgResult').innerHTML = html;
        toast(t('saved_scan'));
      }
    });
  }

  /* ========== SysGuard ========== */
  function renderSysguard(r) {
    const body = document.getElementById('sgBody');
    if (!body) return;
    if (!r) { body.innerHTML = '<p class="empty">' + t('empty_click_sys') + '</p>'; return; }
    const c = r.cpu || {}; const m = r.memory || {}; const d = r.disk || {}; const n = r.network || {};
    const cPct = typeof c.percent === 'number' ? c.percent : null;
    const mPct = typeof m.percent === 'number' ? m.percent : null;
    const dPct = typeof d.max_used_percent === 'number' ? d.max_used_percent : null;
    const nKB = typeof n.throughput_KBps === 'number' ? n.throughput_KBps : null;
    let html = `
      <div class="sys-grid">
        <div class="sys-tile"><label>CPU</label><div class="pct">${cPct === null ? '—' : cPct + '%'}</div>
          <div class="meta">Cores: ${c.count_logical ?? '?'} · Avg ${c.baseline ? c.baseline.average : '?'}%</div></div>
        <div class="sys-tile"><label>RAM</label><div class="pct">${mPct === null ? '—' : mPct + '%'}</div>
          <div class="meta">${m.used_gb ?? '?'}/${m.total_gb ?? '?'} GB</div></div>
        <div class="sys-tile"><label>Disk (max)</label><div class="pct">${dPct === null ? '—' : dPct + '%'}</div>
          <div class="meta">Partitions: ${(d.partitions || []).length}</div></div>
        <div class="sys-tile"><label>Network</label><div class="pct">${nKB === null ? '—' : (nKB > 1024 ? (nKB/1024).toFixed(2)+' MB/s' : nKB.toFixed(1)+' KB/s')}</div>
          <div class="meta">Connections: ${n.connections_count ?? '?'}</div></div>
      </div>
    `;
    if (m && m.swap) html += `<div class="kv"><div><span>Swap used</span><span>${m.swap.percent}% (${m.swap.used_gb}/${m.swap.total_gb} GB)</span></div></div>`;
    if (r.anomalies && r.anomalies.length) {
      html += '<div class="sys-anomalies"><strong>Anomalies:</strong><ul style="margin:6px 0 0 18px;padding:0">' +
        r.anomalies.map(a => `<li>${escapeHtml(a.type)}: ${escapeHtml(a.message)} (value ${a.value})</li>`).join('') +
        '</ul></div>';
    }
    if (r.top_processes && r.top_processes.length) {
      html += '<div class="sys-top"><h4>Top processes</h4><table class="data-table"><thead><tr>' +
        '<th>PID</th><th>Name</th><th>User</th><th>CPU%</th><th>Mem%</th></tr></thead><tbody>' +
        r.top_processes.map(p => `<tr><td>${p.pid}</td><td>${escapeHtml(p.name||'')}</td><td>${escapeHtml(p.user||'')}</td><td>${p.cpu_percent}</td><td>${p.memory_percent}</td></tr>`).join('') +
        '</tbody></table></div>';
    }
    body.innerHTML = html;
  }
  async function runSysguardOnce() {
    const r = await api('GET', '/api/sysguard/status', undefined, {silent: true});
    if (r.ok && r.data) {
      renderSysguard(r.data);
      // also update mini snapshot on overview if it exists
      const mini = document.getElementById('sysSnapshot');
      if (mini) {
        const d = r.data;
        mini.innerHTML = `
          <div class="sys-grid">
            <div class="sys-tile"><label>CPU</label><div class="pct">${d.cpu?.percent ?? '—'}%</div></div>
            <div class="sys-tile"><label>RAM</label><div class="pct">${d.memory?.percent ?? '—'}%</div></div>
            <div class="sys-tile"><label>Disk</label><div class="pct">${d.disk?.max_used_percent ?? '—'}%</div></div>
            <div class="sys-tile"><label>Net</label><div class="pct">${(d.network?.throughput_KBps ?? 0) >= 1024 ? (d.network.throughput_KBps/1024).toFixed(2)+' MB/s' : (d.network?.throughput_KBps ?? 0).toFixed(0)+' KB/s'}</div></div>
          </div>`;
      }
    }
  }
  async function loadSysguardHistory() {
    const r = await api('GET', '/api/sysguard/history', undefined, {silent: true});
    const box = document.getElementById('sgHistory');
    if (!box) return;
    if (!r.ok || !r.data) { box.innerHTML = '<p class="empty">—</p>'; return; }
    const d = r.data;
    const rows = n => (arr) => {
      const a = arr.slice(-n || []);
      const max = Math.max(1, ...a.map(x => Number(x)||0));
      return a.map(v => `<span style="height:${Math.max(6, ((Number(v)||0)/max)*100)}%"></span>`).join('');
    };
    const n = 60;
    box.innerHTML = `<div class="history-chart">
      <div><h4>CPU %</h4><div class="mini-chart">${rows(n)(d.cpu || [])}</div></div>
      <div><h4>RAM %</h4><div class="mini-chart">${rows(n)(d.memory || [])}</div></div>
      <div><h4>Disk %</h4><div class="mini-chart">${rows(n)(d.disk || [])}</div></div>
      <div><h4>Net KB/s</h4><div class="mini-chart">${rows(n)(d.network_KBps || [])}</div></div>
    </div>`;
  }
  function bindSysguard() {
    const once = document.getElementById('sgOnce');
    const stream = document.getElementById('sgStream');
    if (once) once.addEventListener('click', () => { runSysguardOnce(); loadSysguardHistory(); });
    if (stream) stream.addEventListener('click', () => {
      if (state.streamTimer) {
        clearInterval(state.streamTimer); state.streamTimer = null;
        stream.textContent = t('sg_start');
      } else {
        runSysguardOnce(); loadSysguardHistory();
        state.streamTimer = setInterval(() => { runSysguardOnce(); loadSysguardHistory(); }, 5000);
        stream.textContent = t('sg_stop');
      }
    });
  }

  /* ========== CamGuard ========== */
  function bindCamguard() {
    const form = document.getElementById('camguardForm');
    if (!form) return;
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = document.getElementById('cgError'); if (errEl) errEl.textContent = '';
      const fd = new FormData(form);
      const hasFile = fd.get('frame') && fd.get('frame').size > 0;
      const hasB64 = (fd.get('base64') || '').toString().trim().length > 0;
      if (!hasFile && !hasB64) { if (errEl) errEl.textContent = 'Upload frame or paste base64.'; return; }
      let res;
      if (hasFile) {
        const body = new FormData();
        body.append('frame', fd.get('frame'));
        body.append('camera_id', fd.get('camera_id') || 'default');
        body.append('yolo', fd.get('yolo') ? 'true' : 'false');
        res = await api('POST', '/api/camguard/analyze', body);
      } else {
        res = await api('POST', '/api/camguard/analyze', {
          base64: fd.get('base64').toString(),
          camera_id: fd.get('camera_id') || 'default',
          yolo: !!fd.get('yolo')
        });
      }
      if (res.ok && res.data) {
        const r = res.data;
        riskChip(document.getElementById('cgRiskChip'), r.risk_score, r.risk_level);
        document.getElementById('cgResultCard').style.display = '';
        const motion = r.motion || {}; const y = r.yolo || {}; const s = r.scene || {};
        const html = `
          <div class="kv">
            <div><span>Camera</span><span>${escapeHtml(r.camera_id || 'default')}</span></div>
            <div><span>Motion</span><span>${motion.detected ? 'YES' : 'no'} (score ${motion.motion_score ?? 0})</span></div>
            <div><span>Motion regions</span><span>${motion.bboxes ? motion.bboxes.length : 0}</span></div>
            <div><span>YOLO detections</span><span>${y.detection_count ?? 0}</span></div>
            <div><span>People</span><span>${s.people_count ?? 0}</span></div>
            <div><span>Vehicles</span><span>${s.vehicle_count ?? 0}</span></div>
            <div><span>Weapons</span><span>${s.weapon_count ?? 0}</span></div>
            <div><span>Tags</span><span>${(s.tags || []).join(', ') || '—'}</span></div>
          </div>
          ${y.status && y.status.loaded === false && y.status.note ? `<p class="note info-note">${escapeHtml(y.status.note)}</p>` : ''}
          ${y.detection_count > 0 ? `<h4 style="margin:14px 0 6px">YOLO Detections</h4>${jsonBlockHTML(y.detections || [])}` : ''}
          ${motion.bboxes && motion.bboxes.length ? `<h4 style="margin:14px 0 6px">Motion boxes</h4>${jsonBlockHTML(motion.bboxes)}` : ''}
        `;
        document.getElementById('cgResult').innerHTML = html;
        toast(t('saved_scan'));
      }
    });
  }

  /* ========== ScanGuard ========== */
  function bindScanguard() {
    const form = document.getElementById('scanguardForm');
    if (!form) return;
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = document.getElementById('scanGError'); if (errEl) errEl.textContent = '';
      const fd = new FormData(form);
      const hasFile = fd.get('file') && fd.get('file').size > 0;
      const hasCode = (fd.get('code') || '').toString().trim().length > 0;
      if (!hasFile && !hasCode) { if (errEl) errEl.textContent = 'Upload a file or paste text.'; return; }
      let res;
      if (hasFile) {
        const body = new FormData();
        body.append('file', fd.get('file'));
        body.append('type', fd.get('type') || 'auto');
        res = await api('POST', '/api/scanguard/analyze', body);
      } else {
        res = await api('POST', '/api/scanguard/analyze', { code: fd.get('code').toString(), type: fd.get('type') || 'auto' });
      }
      if (res.ok && res.data) {
        const r = res.data;
        riskChip(document.getElementById('scanGRiskChip'), r.risk_score, r.risk_level);
        document.getElementById('scanGResultCard').style.display = '';
        const cat = r.category_summary || {};
        const cats = Object.keys(cat).map(k => `<div><span>${escapeHtml(k)}</span><span>${cat[k].count} issues (Σ${cat[k].severity_sum})</span></div>`).join('');
        const html = `
          <div class="kv">
            <div><span>Detected type</span><span>${escapeHtml(r.detected_input_type || '—')}</span></div>
            <div><span>Total issues</span><span>${r.total_issues_found ?? 0}</span></div>
            <div><span>Risk</span><span>${r.risk_score ?? 0}</span></div>
            ${r.stats ? `<div><span>Lines of code/log</span><span>${r.stats.code_lines ?? 0} / ${r.stats.total_lines ?? 0}</span></div>` : ''}
          </div>
          <h4 style="margin:14px 0 6px">Summary by category</h4>
          <div class="kv">${cats}</div>
          <h4 style="margin:14px 0 6px">Findings</h4>
          ${jsonBlockHTML(r.findings || {})}
        `;
        document.getElementById('scanGResult').innerHTML = html;
        toast(t('saved_scan'));
      }
    });
  }

  /* ========== Alerts & History ========== */
  async function loadAlerts() {
    const sev = document.getElementById('alertSeverityFilter')?.value || '';
    const unr = document.getElementById('alertUnreadOnly')?.checked;
    const q = new URLSearchParams();
    if (sev) q.set('severity', sev);
    if (unr) q.set('unread_only', 'true');
    q.set('per_page', '100');
    const r = await api('GET', '/api/alerts?' + q.toString(), undefined, {silent: true});
    const rows = (r.ok && r.data) ? (r.data.alerts || []) : [];
    renderAlertTable(document.getElementById('alertsTable'), rows, 1000, true);
  }
  async function loadScanHistory() {
    const mod = document.getElementById('scanModuleFilter')?.value || '';
    const min = document.getElementById('scanMinRisk')?.value;
    const q = new URLSearchParams();
    if (mod) q.set('module', mod);
    if (min !== '' && min !== null && min !== undefined) q.set('min_risk', String(min));
    q.set('per_page', '100');
    const r = await api('GET', '/api/scans?' + q.toString(), undefined, {silent: true});
    const rows = (r.ok && r.data) ? (r.data.scans || []) : [];
    renderScanTable(document.getElementById('historyTable'), rows, 1000);
  }
  function bindFilters() {
    const sev = document.getElementById('alertSeverityFilter');
    const unr = document.getElementById('alertUnreadOnly');
    if (sev) sev.addEventListener('change', loadAlerts);
    if (unr) unr.addEventListener('change', loadAlerts);
    const mod = document.getElementById('scanModuleFilter');
    const mr = document.getElementById('scanMinRisk');
    if (mod) mod.addEventListener('change', loadScanHistory);
    if (mr) mr.addEventListener('input', () => clearTimeout(mr._t, mr._t = setTimeout(loadScanHistory, 260)));
  }

  /* ========== Init ========== */
  function init() {
    applyI18n();
    bindLangSwitches();
    // landing only has lang switches (no dashboard bindings)
    if (!document.querySelector('.dashboard-page')) return;
    updateAuthUI();
    bindAuth();
    bindNav();
    bindDocguard();
    bindMailguard();
    bindSysguard();
    bindCamguard();
    bindScanguard();
    bindFilters();
    // initial loads
    if (state.token || (document.getElementById('guestBtn') && document.getElementById('guestBtn').dataset.guestActive === '1')) {
      refreshDashboardSummary();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
