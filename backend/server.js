/* ============================================================
   Бэкенд курса «Зелёный»
   - регистрация / вход (контакт = e-mail или телефон + пароль)
   - серверная проверка доступа (оплату нельзя подделать в браузере)
   - приём вебхука об оплате от платёжной системы
   - прокси для ИИ-объяснений (ключ API хранится только на сервере)
   - учёт посещений и статистика (регистрации / оплаты / визиты)
   Хранилище — обычный JSON-файл (data.json), без сборки и баз данных.
   Запуск: npm install  &&  npm start   (нужен Node.js 18+)
   ============================================================ */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const {
  PORT = 8080,
  JWT_SECRET,
  PAYMENT_WEBHOOK_SECRET,
  ADMIN_TOKEN,
  ALLOWED_ORIGIN = '*',
  DB_PATH = 'data.json',
  SERVE_STATIC = '',
  // ---- настройки ИИ ----
  AI_PROVIDER = 'mistral',                 // mistral | groq | anthropic
  AI_API_KEY,                              // ключ выбранного провайдера
  AI_MODEL,                                // если пусто — берётся модель по умолчанию
  AI_REQUIRE_SUBSCRIPTION = ''             // 'true' => ИИ только для оплативших
} = process.env;

if (!JWT_SECRET) { console.error('Ошибка: задайте JWT_SECRET в файле .env'); process.exit(1); }

// модель по умолчанию под выбранного провайдера
const MODEL = AI_MODEL || (
  AI_PROVIDER === 'groq'      ? 'llama-3.3-70b-versatile' :
  AI_PROVIDER === 'anthropic' ? 'claude-haiku-4-5-20251001' :
                                'mistral-small-latest'      // mistral
);
const REQUIRE_SUB = String(AI_REQUIRE_SUBSCRIPTION) === 'true';

/* ---------- хранилище: простой JSON-файл ---------- */
let DB = { users: [], metrics: {}, seq: 0 };
try { if (fs.existsSync(DB_PATH)) DB = JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); } catch (e) { console.error('Не удалось прочитать', DB_PATH, e.message); }
DB.users = DB.users || []; DB.metrics = DB.metrics || {}; DB.seq = DB.seq || 0; DB.promos = DB.promos || []; DB.sales = DB.sales || [];
let saveTimer = null;
function save() { clearTimeout(saveTimer); saveTimer = setTimeout(() => { try { fs.writeFileSync(DB_PATH, JSON.stringify(DB)); } catch (e) { console.error('save error', e.message); } }, 50); }

const todayStr = () => new Date().toISOString().slice(0, 10);
const getUser = id => DB.users.find(u => u.id === id);
const getByEmail = e => { const k = (e || '').trim().toLowerCase(); return DB.users.find(u => u.email === k); };

/* ---------- приложение ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: ALLOWED_ORIGIN === '*' ? true : ALLOWED_ORIGIN.split(',').map(s => s.trim()) }));

/* вебхук читаем «сырым», чтобы проверить подпись; остальное — как JSON */
app.use('/api/payment/webhook', express.raw({ type: '*/*' }));
app.use((req, res, next) => {
  if (req.path === '/api/payment/webhook') return next();
  express.json({ limit: '1mb' })(req, res, next);
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 });
const aiLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });

/* ---------- помощники ---------- */
function sign(user) { return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '60d' }); }
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'no_token' });
  try { req.userId = jwt.verify(t, JWT_SECRET).id; next(); }
  catch (e) { return res.status(401).json({ error: 'bad_token' }); }
}
function isActive(u) {
  if (!u || !u.paid) return false;
  if (u.paid_until) return new Date(u.paid_until).getTime() > Date.now();
  return true; // доступ навсегда
}
const publicUser = u => ({ name: u.name, email: u.email, paid: isActive(u), plan: u.plan, paid_until: u.paid_until });
function grant(user, plan, source) {
  let until = null;
  if (plan === 'month') { const d = new Date(); d.setDate(d.getDate() + 30); until = d.toISOString(); }
  user.paid = 1; user.plan = plan; user.paid_until = until;
  // журнал выдачи доступа (для админ-панели)
  const price = plan === 'month' ? 499 : plan === 'full' ? 990 : 0;
  DB.sales.push({ email: user.email, plan, price, source: source || 'manual', time: new Date().toISOString() });
  if (DB.sales.length > 100000) DB.sales = DB.sales.slice(-100000);
  save();
}

/* ---------- регистрация (контакт = e-mail или телефон + пароль) ---------- */
app.post('/api/register', authLimiter, (req, res) => {
  const login = ((req.body || {}).login || (req.body || {}).email || '').trim().toLowerCase();
  const password = (req.body || {}).password || '';
  if (!login || password.length < 6)
    return res.status(400).json({ error: 'Укажите e-mail или телефон и пароль (от 6 символов)' });
  if (getByEmail(login)) return res.status(409).json({ error: 'Такой контакт уже зарегистрирован' });
  const isPhone = /^[+\d][\d\s\-()]{6,}$/.test(login);
  const u = {
    id: ++DB.seq, name: login, email: login, phone: isPhone ? login : '',
    pass_hash: bcrypt.hashSync(password, 10), paid: 0, plan: null, paid_until: null,
    created_at: new Date().toISOString()
  };
  DB.users.push(u); save();
  res.json({ token: sign(u), user: publicUser(u) });
});

/* ---------- вход ---------- */
app.post('/api/login', authLimiter, (req, res) => {
  const login = ((req.body || {}).login || (req.body || {}).email || '');
  const password = (req.body || {}).password;
  const u = getByEmail(login);
  if (!u || !bcrypt.compareSync(password || '', u.pass_hash))
    return res.status(401).json({ error: 'Неверный контакт или пароль' });
  res.json({ token: sign(u), user: publicUser(u) });
});

/* ---------- кто я / есть ли доступ ---------- */
app.get('/api/me', auth, (req, res) => {
  const u = getUser(req.userId);
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json({ user: publicUser(u) });
});

/* ---------- вебхук оплаты (вызывает платёжная система) ----------
   Подпись проверяется как HMAC-SHA256 от тела запроса.
   Поля (email/login, plan) и заголовок подписи подстройте под вашего провайдера. */
app.post('/api/payment/webhook', (req, res) => {
  const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body || {});
  if (PAYMENT_WEBHOOK_SECRET) {
    const sig = req.headers['x-signature'] || '';
    const expected = crypto.createHmac('sha256', PAYMENT_WEBHOOK_SECRET).update(raw).digest('hex');
    if (sig !== expected) return res.status(401).json({ error: 'bad_signature' });
  }
  let data; try { data = JSON.parse(raw); } catch (e) { return res.status(400).json({ error: 'bad_json' }); }
  const u = getByEmail(data.email || data.login);
  if (!u) return res.status(404).json({ error: 'user_not_found' });
  grant(u, data.plan || 'full', 'payment');
  res.json({ ok: true });
});

/* ---------- ручная выдача доступа (ручные продажи / тест) ---------- */
app.post('/api/admin/grant', (req, res) => {
  if (!ADMIN_TOKEN || (req.headers['x-admin-token'] || '') !== ADMIN_TOKEN)
    return res.status(403).json({ error: 'forbidden' });
  const u = getByEmail((req.body || {}).email || (req.body || {}).login);
  if (!u) return res.status(404).json({ error: 'user_not_found' });
  grant(u, (req.body || {}).plan || 'full', 'manual');
  res.json({ ok: true });
});

/* ---------- забрать доступ (вернуть на бесплатный) ---------- */
app.post('/api/admin/revoke', (req, res) => {
  if (!ADMIN_TOKEN || (req.headers['x-admin-token'] || '') !== ADMIN_TOKEN)
    return res.status(403).json({ error: 'forbidden' });
  const u = getByEmail((req.body || {}).email || (req.body || {}).login);
  if (!u) return res.status(404).json({ error: 'user_not_found' });
  u.paid = 0; u.plan = null; u.paid_until = null; save();
  res.json({ ok: true });
});

/* ---------- промокоды ---------- */

// Создать промокод (админ)
app.post('/api/admin/promo/create', (req, res) => {
  if (!ADMIN_TOKEN || (req.headers['x-admin-token'] || '') !== ADMIN_TOKEN)
    return res.status(403).json({ error: 'forbidden' });
  const { code, plan = 'full', max_uses = 1, note = '' } = req.body || {};
  const key = (code || '').trim().toUpperCase();
  if (!key) return res.status(400).json({ error: 'Укажите код' });
  if (DB.promos.find(p => p.code === key)) return res.status(409).json({ error: 'Такой код уже существует' });
  const promo = { code: key, plan, max_uses: Number(max_uses) || 1, uses: 0, note, created_at: new Date().toISOString(), used_by: [] };
  DB.promos.push(promo); save();
  res.json({ ok: true, promo });
});

// Список промокодов (админ)
app.get('/api/admin/promo/list', (req, res) => {
  if (!ADMIN_TOKEN || (req.headers['x-admin-token'] || '') !== ADMIN_TOKEN)
    return res.status(403).json({ error: 'forbidden' });
  res.json({ promos: DB.promos });
});

// Удалить промокод (админ)
app.delete('/api/admin/promo/:code', (req, res) => {
  if (!ADMIN_TOKEN || (req.headers['x-admin-token'] || '') !== ADMIN_TOKEN)
    return res.status(403).json({ error: 'forbidden' });
  const key = (req.params.code || '').toUpperCase();
  const idx = DB.promos.findIndex(p => p.code === key);
  if (idx === -1) return res.status(404).json({ error: 'not_found' });
  DB.promos.splice(idx, 1); save();
  res.json({ ok: true });
});

// Активировать промокод (пользователь)
app.post('/api/promo/redeem', authLimiter, auth, (req, res) => {
  const u = getUser(req.userId);
  if (!u) return res.status(404).json({ error: 'not_found' });
  const key = ((req.body || {}).code || '').trim().toUpperCase();
  if (!key) return res.status(400).json({ error: 'Укажите промокод' });
  const promo = DB.promos.find(p => p.code === key);
  if (!promo) return res.status(404).json({ error: 'Промокод не найден' });
  if (promo.uses >= promo.max_uses) return res.status(410).json({ error: 'Промокод уже использован' });
  if (promo.used_by.includes(u.id)) return res.status(409).json({ error: 'Вы уже использовали этот промокод' });
  promo.uses++; promo.used_by.push(u.id);
  grant(u, promo.plan, 'promo:' + key);
  res.json({ ok: true, plan: promo.plan, user: publicUser(u) });
});

/* ---------- учёт посещения (сайт пингует при загрузке) ---------- */
app.post('/api/visit', (req, res) => {
  const d = todayStr();
  DB.metrics[d] = (DB.metrics[d] || 0) + 1; save();
  res.json({ ok: true });
});

/* ---------- список всех пользователей (для админ-панели) ---------- */
app.get('/api/admin/users', (req, res) => {
  if (!ADMIN_TOKEN || (req.headers['x-admin-token'] || req.query.token || '') !== ADMIN_TOKEN)
    return res.status(403).json({ error: 'forbidden' });
  const users = DB.users.map(u => ({
    id: u.id, name: u.name, email: u.email, phone: u.phone || '',
    paid: isActive(u), plan: u.plan || null, paid_until: u.paid_until || null,
    created_at: u.created_at
  })).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ users });
});

/* ---------- история выдачи доступа / оплат (для админ-панели) ---------- */
app.get('/api/admin/sales', (req, res) => {
  if (!ADMIN_TOKEN || (req.headers['x-admin-token'] || req.query.token || '') !== ADMIN_TOKEN)
    return res.status(403).json({ error: 'forbidden' });
  const sales = (DB.sales || []).slice(-500).reverse();
  res.json({ sales });
});

/* ---------- статистика (ваш отчёт) ---------- */
app.get('/api/stats', (req, res) => {
  if (!ADMIN_TOKEN || (req.query.token || '') !== ADMIN_TOKEN)
    return res.status(403).json({ error: 'forbidden' });
  const now = Date.now(), weekAgo = now - 7 * 864e5, td = todayStr();
  const regToday = DB.users.filter(u => (u.created_at || '').slice(0, 10) === td).length;
  const regWeek = DB.users.filter(u => new Date(u.created_at).getTime() >= weekAgo).length;
  let visWeek = 0, visTotal = 0;
  for (const day in DB.metrics) {
    const v = DB.metrics[day]; visTotal += v;
    if (new Date(day).getTime() >= weekAgo) visWeek += v;
  }
  const month_users = DB.users.filter(u => isActive(u) && u.plan === 'month').length;
  const full_users  = DB.users.filter(u => isActive(u) && u.plan === 'full').length;
  const revenue = (DB.sales || []).reduce((s, x) => s + (x.price || 0), 0);
  res.json({
    total_users: DB.users.length,
    paid_users: DB.users.filter(u => isActive(u)).length,
    month_users, full_users, revenue,
    registrations_today: regToday,
    registrations_week: regWeek,
    visits_today: DB.metrics[td] || 0,
    visits_week: visWeek,
    visits_total: visTotal
  });
});

/* ---------- ИИ-объяснение ----------
   Провайдер выбирается переменной AI_PROVIDER (по умолчанию mistral — бесплатно).
   Подписка по умолчанию НЕ требуется; включается через AI_REQUIRE_SUBSCRIPTION=true. */
app.post('/api/ai/explain', aiLimiter, auth, async (req, res) => {
  const u = getUser(req.userId);
  if (REQUIRE_SUB && !isActive(u)) return res.status(403).json({ error: 'Доступно по подписке' });
  if (!AI_API_KEY) { console.error('ИИ: не задан AI_API_KEY'); return res.status(500).json({ error: 'AI не настроен на сервере' }); }
  const { question, correct } = req.body || {};
  if (!question || !correct) return res.status(400).json({ error: 'bad_request' });
  const prompt = 'Ты добрый автоинструктор. Объясни простым коротким языком, 3-4 предложения, без сложных терминов и без списков, можно с бытовым примером, почему на вопрос по ПДД «' + question + '» правильный ответ — «' + correct + '».';
  try {
    const text = await callAI(prompt);
    res.json({ text: text || 'Не удалось получить объяснение, попробуйте ещё раз.' });
  } catch (e) {
    console.error('ИИ ошибка:', e.message);
    res.status(502).json({ error: 'ai_failed' });
  }
});

/* Универсальный вызов ИИ под выбранного провайдера */
async function callAI(prompt) {
  // Mistral и Groq — одинаковый OpenAI-совместимый формат, отличается только адрес
  if (AI_PROVIDER === 'mistral' || AI_PROVIDER === 'groq') {
    const url = AI_PROVIDER === 'mistral'
      ? 'https://api.mistral.ai/v1/chat/completions'
      : 'https://api.groq.com/openai/v1/chat/completions';
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'authorization': 'Bearer ' + AI_API_KEY },
      body: JSON.stringify({ model: MODEL, max_tokens: 400, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(AI_PROVIDER + ' ' + r.status + ' ' + JSON.stringify(data));
    return (((data.choices || [])[0] || {}).message || {}).content?.trim() || '';
  }
  // Anthropic (платно)
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': AI_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: MODEL, max_tokens: 400, messages: [{ role: 'user', content: prompt }] })
  });
  const data = await r.json();
  if (!r.ok) throw new Error('anthropic ' + r.status + ' ' + JSON.stringify(data));
  return (data.content || []).map(b => b && b.type === 'text' ? b.text : '').join('').trim();
}

/* ---------- (необязательно) отдавать сам сайт с этого же сервера ---------- */
if (SERVE_STATIC) app.use(express.static(path.resolve(SERVE_STATIC)));

app.listen(PORT, () => console.log('Бэкенд «Зелёный» запущен на порту ' + PORT + ' · ИИ: ' + AI_PROVIDER + '/' + MODEL));
