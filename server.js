require('dotenv').config();
const express = require('express'), path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

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
      id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ DEFAULT now());`);
}

app.post('/api/register', limiter, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !String(name).trim() || !isEmail(email) || typeof password !== 'string' || password.length < 6)
    return res.status(400).json({ error: 'Enter your name, a valid email and a password of 6+ characters' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows: [u] } = await pool.query('INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email',
      [String(name).trim().slice(0, 100), email.toLowerCase(), hash]);
    res.json({ token: sign(u), user: { name: u.name, email: u.email } });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email already registered – please sign in' });
    console.error(e); res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', limiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const { rows: [u] } = await pool.query('SELECT * FROM users WHERE email=$1', [String(email || '').toLowerCase()]);
    if (!u) return res.status(404).json({ error: 'No account found – please register first' });
    if (!(await bcrypt.compare(String(password || ''), u.password_hash))) return res.status(401).json({ error: 'Incorrect password' });
    res.json({ token: sign(u), user: { name: u.name, email: u.email } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

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
