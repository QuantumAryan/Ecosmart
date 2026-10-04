require('dotenv').config();
const express = require('express'), path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer'), crypto = require('crypto'), dns = require('dns').promises;

if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) { console.error('Missing DATABASE_URL or JWT_SECRET in .env'); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Create tables once per server instance (works locally and on Vercel serverless)
let ready = null;
const ensure = () => ready || (ready = init().catch(e => { ready = null; throw e; }));
app.use('/api', async (req, res, next) => {
  try { await ensure(); next(); } catch (e) { console.error(e); res.status(500).json({ error: 'Database unavailable' }); }
});

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 40, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts, try again later' } });
const sign = u => jwt.sign({ id: u.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
const auth = (req, res, next) => {
  try { req.uid = jwt.verify((req.headers.authorization || '').slice(7), process.env.JWT_SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Please sign in' }); }
};
const isEmail = e => typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length < 255;

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS survey_responses (
      id SERIAL PRIMARY KEY, user_id INT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      answers INT[] NOT NULL, score INT NOT NULL, pct INT NOT NULL, interest TEXT,
      created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS subscribers (
      id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS device_marks (
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, device TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('using','plan')), PRIMARY KEY (user_id, device, kind));
    CREATE TABLE IF NOT EXISTS checklist (
      user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, items INT[] NOT NULL DEFAULT '{}');
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE users ALTER COLUMN verified SET DEFAULT TRUE;
    UPDATE users SET verified=true WHERE verified=false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_expires TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_sent_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_attempts INT NOT NULL DEFAULT 0;`);
}

const wrap = fn => (req, res, next) => fn(req, res, next).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
// ---------- notification emails (no OTP) ----------
const FROM = 'EcoSmart <' + (process.env.SMTP_FROM || process.env.SMTP_USER || 'leave.ecosmart@gmail.com') + '>';
let transporter = null;
async function sendMail(to, subject, text, html) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) { console.log('[mail skipped - SMTP not configured]', subject, '->', to); return; }
  const pass = process.env.SMTP_PASS.replace(/[\s"']/g, ''), user = process.env.SMTP_USER.trim();
  if (!transporter) {
    const port = +process.env.SMTP_PORT || 587;
    transporter = process.env.SMTP_HOST
      ? nodemailer.createTransport({ host: process.env.SMTP_HOST.trim(), port, secure: port === 465, auth: { user, pass } })
      : nodemailer.createTransport({ service: 'gmail', auth: { user, pass } });
  }
  await transporter.sendMail({ from: FROM, to, subject, text, html });
}
const esc = s => String(s).replace(/[<>&"]/g, '');
async function notify(u, kind) { // never blocks or breaks sign-in if email fails
  const name = esc(u.name), reg = kind === 'register';
  const when = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'short' }) + ' IST';
  const subject = reg ? 'Welcome to EcoSmart – registration successful' : 'EcoSmart – you signed in successfully';
  const line = reg ? `Your EcoSmart account was created successfully on ${when}. Thank you for joining us in the fight against climate change!`
                   : `You signed in to EcoSmart successfully on ${when}. If this was not you, please contact leave.ecosmart@gmail.com right away.`;
  const text = `Hi ${name},\n\n${line}\n\nEcoSmart – North Rampuri, Muzaffarnagar 251002`;
  const html = `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:16px"><h2 style="color:#16a34a;margin:0 0 8px">🌿 EcoSmart</h2><p>Hi ${name},</p><p>${esc(line)}</p><p style="color:#64748b;font-size:13px">EcoSmart – North Rampuri, Muzaffarnagar 251002</p></div>`;
  try { await Promise.race([sendMail(u.email, subject, text, html), new Promise((_, rej) => setTimeout(() => rej(new Error('mail timeout')), 8000))]); }
  catch (e) { console.error('Mail error:', e.message); }
}
async function domainOk(email) { // does the email domain really accept mail?
  const d = email.split('@')[1];
  try { const r = await dns.resolveMx(d); if (r && r.length) return true; } catch (e) { if (e.code !== 'ENODATA' && e.code !== 'ENOTFOUND') return true; }
  try { const a = await dns.resolve4(d); return a.length > 0; } catch (e) { return !(e.code === 'ENODATA' || e.code === 'ENOTFOUND'); }
}

app.post('/api/register', limiter, wrap(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !String(name).trim() || !isEmail(email) || typeof password !== 'string' || password.length < 6)
    return res.status(400).json({ error: 'Enter your name, a valid email and a password of 6+ characters' });
  const em = email.toLowerCase();
  if (!(await domainOk(em))) return res.status(400).json({ error: 'That email domain does not exist. Please check the address.' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const { rows: [u] } = await pool.query('INSERT INTO users(name,email,password_hash,verified) VALUES($1,$2,$3,true) RETURNING id,name,email',
      [String(name).trim().slice(0, 100), em, hash]);
    await notify(u, 'register');
    res.json({ token: sign(u), user: { name: u.name, email: u.email } });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email already registered – please sign in' });
    throw e;
  }
}));

app.post('/api/login', limiter, wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const { rows: [u] } = await pool.query('SELECT * FROM users WHERE email=$1', [String(email || '').toLowerCase()]);
  if (!u) return res.status(404).json({ error: 'No account found – please register first' });
  if (!(await bcrypt.compare(String(password || ''), u.password_hash))) return res.status(401).json({ error: 'Incorrect password' });
  await notify(u, 'login');
  res.json({ token: sign(u), user: { name: u.name, email: u.email } });
}));

app.get('/api/me', auth, async (req, res) => {
  const { rows: [u] } = await pool.query('SELECT name,email FROM users WHERE id=$1', [req.uid]);
  u ? res.json({ user: u }) : res.status(401).json({ error: 'Please sign in' });
});

app.get('/api/survey', auth, async (req, res) => {
  const { rows: [r] } = await pool.query('SELECT answers AS a, score, pct, interest FROM survey_responses WHERE user_id=$1', [req.uid]);
  res.json({ result: r || null });
});

app.post('/api/survey', auth, async (req, res) => {
  const { a, interest } = req.body || {};
  if (!Array.isArray(a) || a.length !== 6 || a.some(n => ![0, 1, 2, 3].includes(n))) return res.status(400).json({ error: 'Invalid answers' });
  const score = a.reduce((x, y) => x + y, 0), pct = Math.round(score / 18 * 100);
  await pool.query(`INSERT INTO survey_responses(user_id,answers,score,pct,interest) VALUES($1,$2,$3,$4,$5)
    ON CONFLICT (user_id) DO UPDATE SET answers=$2, score=$3, pct=$4, interest=$5, created_at=now()`,
    [req.uid, a, score, pct, String(interest || '').slice(0, 60) || null]);
  res.json({ ok: true });
});

app.delete('/api/survey', auth, async (req, res) => {
  await pool.query('DELETE FROM survey_responses WHERE user_id=$1', [req.uid]);
  res.json({ ok: true });
});

app.get('/api/stats', async (req, res) => {
  const { rows: [r] } = await pool.query('SELECT COUNT(*)::int AS n, COALESCE(ROUND(AVG(pct)),0)::int AS avg FROM survey_responses');
  res.json(r);
});

const DEVICES = ['Smart Thermostat','Smart LED Bulbs','Smart Plugs','Energy Monitor','Smart EV Charger','Rooftop Solar','Inverter AC (5-star)','Smart Geyser Timer','BLDC Smart Fan'];

// how many households use each device (public)
app.get('/api/devices/stats', wrap(async (req, res) => {
  const { rows } = await pool.query("SELECT device, COUNT(*)::int AS n FROM device_marks WHERE kind='using' GROUP BY device");
  res.json(Object.fromEntries(rows.map(r => [r.device, r.n])));
}));

// everything saved for the signed-in user
app.get('/api/mydata', auth, wrap(async (req, res) => {
  const [m, c, s] = await Promise.all([
    pool.query('SELECT device, kind FROM device_marks WHERE user_id=$1', [req.uid]),
    pool.query('SELECT items FROM checklist WHERE user_id=$1', [req.uid]),
    pool.query('SELECT pct FROM survey_responses WHERE user_id=$1', [req.uid])]);
  res.json({ using: m.rows.filter(r => r.kind === 'using').map(r => r.device), plan: m.rows.filter(r => r.kind === 'plan').map(r => r.device),
    checklist: c.rows[0] ? c.rows[0].items : null, survey: s.rows[0] ? s.rows[0].pct : null });
}));

app.post('/api/devices/use', auth, wrap(async (req, res) => {
  const { device, on } = req.body || {};
  if (!DEVICES.includes(device)) return res.status(400).json({ error: 'Unknown device' });
  if (on) await pool.query("INSERT INTO device_marks(user_id,device,kind) VALUES($1,$2,'using') ON CONFLICT DO NOTHING", [req.uid, device]);
  else await pool.query("DELETE FROM device_marks WHERE user_id=$1 AND device=$2 AND kind='using'", [req.uid, device]);
  res.json({ ok: true });
}));

app.post('/api/devices/plan', auth, wrap(async (req, res) => {
  const d = (req.body || {}).devices;
  if (!Array.isArray(d) || d.some(x => !DEVICES.includes(x))) return res.status(400).json({ error: 'Invalid devices' });
  await pool.query("DELETE FROM device_marks WHERE user_id=$1 AND kind='plan'", [req.uid]);
  if (d.length) await pool.query("INSERT INTO device_marks(user_id,device,kind) SELECT $1, UNNEST($2::text[]), 'plan' ON CONFLICT DO NOTHING", [req.uid, [...new Set(d)]]);
  res.json({ ok: true });
}));

app.post('/api/checklist', auth, wrap(async (req, res) => {
  const i = (req.body || {}).items;
  if (!Array.isArray(i) || i.some(n => !Number.isInteger(n) || n < 0 || n > 20)) return res.status(400).json({ error: 'Invalid items' });
  await pool.query('INSERT INTO checklist(user_id,items) VALUES($1,$2) ON CONFLICT (user_id) DO UPDATE SET items=$2', [req.uid, [...new Set(i)]]);
  res.json({ ok: true });
}));

// delete own account and all data (needs password)
app.delete('/api/me', auth, wrap(async (req, res) => {
  const { rows: [u] } = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.uid]);
  if (!u || !(await bcrypt.compare(String((req.body || {}).password || ''), u.password_hash))) return res.status(401).json({ error: 'Incorrect password' });
  await pool.query('DELETE FROM users WHERE id=$1', [req.uid]);
  res.json({ ok: true });
}));

app.post('/api/subscribe', limiter, async (req, res) => {
  const { email } = req.body || {};
  if (!isEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  await pool.query('INSERT INTO subscribers(email) VALUES($1) ON CONFLICT DO NOTHING', [email.toLowerCase()]);
  res.json({ ok: true });
});

if (require.main === module) {
  ensure().then(() => app.listen(process.env.PORT || 3000, () => console.log('EcoSmart running on http://localhost:' + (process.env.PORT || 3000))))
    .catch(e => { console.error('Database connection failed:', e.message); process.exit(1); });
}
module.exports = app; // used by Vercel (api/index.js)
