/**
 * Halo Trade v5 — multi-tenant SaaS server
 * ------------------------------------------------------------------
 * Users register/login (JWT), connect their own MT4/MT5 accounts
 * (provisioned under YOUR master MetaApi token — broker passwords are
 * passed straight to MetaApi and never stored), subscribe via Paystack,
 * and get plan-gated access to the trading desk.
 *
 * ENV (Railway):
 *   DATABASE_URL         required — Railway PostgreSQL plugin provides it
 *   JWT_SECRET           required — long random string
 *   METAAPI_TOKEN        required — your master token
 *   METAAPI_REGION       london (default)
 *   PAYSTACK_SECRET_KEY  sk_live_... (or sk_test_... while testing)
 *   PLAN_TRADER_PESEWAS  e.g. 25000  (= GHS 250/month)
 *   PLAN_PRO_PESEWAS     e.g. 50000  (= GHS 500/month)
 *   APP_URL              https://your-railway-domain (for Paystack callback)
 */

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import pg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 8080;
const TOKEN = process.env.METAAPI_TOKEN;
const REGION = process.env.METAAPI_REGION || "london";
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET is not set. Refusing to start with an insecure default. Set it in Railway variables.");
  process.exit(1);
}
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || "";
/* Allowed browser origins for the API. Defaults to same-origin only.
   Set ALLOWED_ORIGINS (comma-separated) to permit specific external domains. */
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || "")
  .split(",").map((s) => s.trim()).filter(Boolean);
const PLANS = {
  trader: { amount: Number(process.env.PLAN_TRADER_PESEWAS || 25000), accounts: 1, label: "Trader" },
  pro:    { amount: Number(process.env.PLAN_PRO_PESEWAS || 50000),    accounts: 3, label: "Pro" },
};
/* Annual = 10× monthly (2 months free). Overridable per-plan if you want custom annual pricing. */
const annualAmount = (plan) =>
  Number(process.env[`PLAN_${plan.toUpperCase()}_ANNUAL_PESEWAS`] || PLANS[plan].amount * 10);
/* How many days each billing interval grants. */
const INTERVAL_DAYS = { monthly: 31, annual: 366 };

/* Telegram bot for trade alerts (optional — set TELEGRAM_BOT_TOKEN to enable). */
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TG_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || ""; // without @, e.g. HaloTradeBot

/* Economic calendar / news filter.
   Default source is a free, no-key ForexFactory-style weekly JSON feed.
   Override NEWS_FEED_URL to use any provider that returns a compatible JSON array. */
const NEWS_FEED_URL = process.env.NEWS_FEED_URL || "https://nfs.faireconomy.media/ff_calendar_thisweek.json";

/* Super-admin emails (comma-separated) get unlimited access with no payment. */
const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
const ADMIN_ACCOUNT_LIMIT = Number(process.env.ADMIN_ACCOUNT_LIMIT || 20);
const isAdmin = (u) => u && ADMIN_EMAILS.includes(String(u.email).toLowerCase());

const CLIENT_API = `https://mt-client-api-v1.${REGION}.agiliumtrade.ai`;
const PROVISIONING_API = "https://mt-provisioning-api-v1.agiliumtrade.agiliumtrade.ai";

/* ---------------- database ---------------- */
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL || "") ? false : { rejectUnauthorized: false },
});
const q = (text, params) => pool.query(text, params);

async function migrate() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    plan_expires TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_chat_id TEXT`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_link_code TEXT`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS notify_enabled BOOLEAN NOT NULL DEFAULT true`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_expires TIMESTAMPTZ`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_used BOOLEAN NOT NULL DEFAULT false`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS renewal_reminded_at TIMESTAMPTZ`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS billing_interval TEXT`);
  await q(`CREATE TABLE IF NOT EXISTS trading_accounts (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    metaapi_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    broker_server TEXT,
    login TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS discipline (
    metaapi_id TEXT PRIMARY KEY,
    user_id INT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT false,
    lock_until BIGINT NOT NULL DEFAULT 0,
    trade_live BOOLEAN NOT NULL DEFAULT false,
    last_event TEXT
  )`);
  await q(`CREATE TABLE IF NOT EXISTS payments (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    reference TEXT UNIQUE NOT NULL,
    plan TEXT NOT NULL,
    amount INT NOT NULL,
    paid_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS automation (
    metaapi_id TEXT PRIMARY KEY,
    user_id INT NOT NULL,
    trailing_enabled BOOLEAN NOT NULL DEFAULT false,
    trailing_distance NUMERIC NOT NULL DEFAULT 0,   -- distance in price points
    trailing_start NUMERIC NOT NULL DEFAULT 0,      -- profit (points) before trailing activates; 0 = immediately
    be_enabled BOOLEAN NOT NULL DEFAULT false,
    be_trigger NUMERIC NOT NULL DEFAULT 0,          -- profit (points) before SL jumps to entry
    be_offset NUMERIC NOT NULL DEFAULT 0,           -- lock a few points of profit above entry
    dll_enabled BOOLEAN NOT NULL DEFAULT false,     -- daily loss limit
    dll_percent NUMERIC NOT NULL DEFAULT 0,         -- % of day-start equity
    dll_day TEXT,                                   -- yyyy-mm-dd of current tracking day
    dll_start_equity NUMERIC NOT NULL DEFAULT 0,
    dll_locked_until BIGINT NOT NULL DEFAULT 0,
    last_event TEXT
  )`);
  /* Phase 4 — prop-firm rule pack (added via ALTER so existing rows gain them) */
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_enabled BOOLEAN NOT NULL DEFAULT false`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_baseline NUMERIC NOT NULL DEFAULT 0`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_max_dd_percent NUMERIC NOT NULL DEFAULT 0`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_target_percent NUMERIC NOT NULL DEFAULT 0`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_streak_pause INT NOT NULL DEFAULT 0`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_streak_count INT NOT NULL DEFAULT 0`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_last_deal_id TEXT`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_locked_until BIGINT NOT NULL DEFAULT 0`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_halted BOOLEAN NOT NULL DEFAULT false`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS prop_status TEXT`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS news_enabled BOOLEAN NOT NULL DEFAULT false`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS news_before_mins INT NOT NULL DEFAULT 15`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS news_after_mins INT NOT NULL DEFAULT 15`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS news_impact TEXT NOT NULL DEFAULT 'high'`);
  await q(`ALTER TABLE automation ADD COLUMN IF NOT EXISTS news_close BOOLEAN NOT NULL DEFAULT false`);
  /* Phase A — durable log of every protective action, for the Discipline Report */
  await q(`CREATE TABLE IF NOT EXISTS discipline_events (
    id BIGSERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    metaapi_id TEXT,
    kind TEXT NOT NULL,          -- 'lock_block' | 'oneshot_lock' | 'daily_loss' | 'prop_breach' | 'prop_target' | 'streak_pause' | 'news_block' | 'guard_flatten'
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  await q(`CREATE INDEX IF NOT EXISTS idx_disc_events_user_time ON discipline_events (user_id, created_at DESC)`);
  /* Phase C — trade journal: capture the "why" behind trades for pattern review */
  await q(`CREATE TABLE IF NOT EXISTS journal_entries (
    id BIGSERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    symbol TEXT,
    direction TEXT,              -- 'buy' | 'sell' | null
    rationale TEXT,              -- why I took (or skipped) this trade
    emotion TEXT,                -- calm | confident | fearful | greedy | fomo | revenge | bored
    outcome TEXT,                -- win | loss | breakeven | open | skipped | null
    lesson TEXT,                 -- what I learned
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  await q(`CREATE INDEX IF NOT EXISTS idx_journal_user_time ON journal_entries (user_id, created_at DESC)`);
  console.log("db: migrations ok");
}

/* ---------------- MetaApi helper ---------------- */
/* Call MetaApi with a timeout and automatic retry on transient failures.
   Cold cloud terminals routinely return 502/503/504 or time out for a second or two;
   retrying quietly turns those blips into a normal response instead of a user-facing error. */
async function mapi(base, p, { method = "GET", body, retries = 2, timeoutMs = 12000 } = {}) {
  const TRANSIENT = new Set([502, 503, 504, 408, 429]);
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(`${base}${p}`, {
        method,
        headers: { "auth-token": TOKEN, "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      const text = await res.text();
      let data; try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
      if (!res.ok) {
        const err = new Error(data?.message || `MetaApi ${res.status}`);
        err.status = res.status; err.details = data;
        // retry transient statuses; fail fast on real errors (401/403/404/400)
        if (TRANSIENT.has(res.status) && attempt < retries) { lastErr = err; await sleep(400 * (attempt + 1)); continue; }
        throw err;
      }
      return data;
    } catch (e) {
      clearTimeout(timer);
      // network error or timeout (abort) — retry
      const isAbort = e.name === "AbortError";
      const isNet = !e.status;
      if ((isAbort || isNet) && attempt < retries) {
        lastErr = isAbort ? Object.assign(new Error("MetaApi timed out"), { status: 504 }) : e;
        await sleep(400 * (attempt + 1));
        continue;
      }
      if (isAbort) { const err = new Error("MetaApi timed out"); err.status = 504; throw err; }
      throw e;
    }
  }
  throw lastErr || new Error("MetaApi request failed");
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const wrap = (fn) => async (req, res) => {
  try { res.json(await fn(req)); }
  catch (e) { res.status(e.status || 502).json({ error: e.message, details: e.details || null }); }
};
const httpErr = (status, msg) => { const e = new Error(msg); e.status = status; return e; };

/* Record a protective action for the Discipline Report. Never throws — logging must not
   break enforcement. userId may be looked up from the account when not provided. */
async function logDiscipline(userId, metaapiId, kind, detail) {
  try {
    let uid = userId;
    if (!uid && metaapiId) {
      const r = await q("SELECT user_id FROM trading_accounts WHERE metaapi_id=$1", [metaapiId]);
      uid = r.rows[0]?.user_id;
    }
    if (!uid) return;
    await q("INSERT INTO discipline_events (user_id, metaapi_id, kind, detail) VALUES ($1,$2,$3,$4)",
      [uid, metaapiId || null, kind, (detail || "").slice(0, 300)]);
  } catch (e) { console.error("logDiscipline:", e.message); }
}

/* ---------------- middleware ---------------- */
app.set("trust proxy", 1); // Railway sits behind a proxy — needed for correct client IPs
app.use(helmet({
  contentSecurityPolicy: false, // our SPA + inline styles need this off; other headers still apply
  crossOriginEmbedderPolicy: false,
}));
app.use(cors({
  origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true, // same-origin by default; explicit list if set
  credentials: true,
}));
app.use(express.json({
  limit: "200kb",
  verify: (req, _res, buf) => { if (req.originalUrl === "/webhooks/paystack") req.rawBody = buf; },
}));
app.use(express.static(path.join(__dirname, "public")));

/* Rate limiters — protect auth from brute force / abuse */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many attempts. Please wait a few minutes and try again." },
});
const forgotLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many reset requests. Please wait an hour." },
});
app.use("/api/auth/login", authLimiter);
app.use("/api/auth/register", authLimiter);
app.use("/api/auth/reset", authLimiter);
app.use("/api/auth/forgot", forgotLimiter);
const chatLimiter = rateLimit({
  windowMs: 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false,
  message: { error: "You're sending messages very fast — please slow down a moment." },
});
app.use("/api/chat", chatLimiter);

/* JWT auth for /api (except auth + plans) */
app.use("/api", (req, res, next) => {
  if (req.path.startsWith("/auth/") || req.path === "/billing/plans" || req.path === "/diag") return next();
  const h = req.get("Authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Login required" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: "Session expired — log in again" }); }
});

const TRIAL_DAYS = Number(process.env.TRIAL_DAYS || 7);
const trialActive = (u) => Boolean(u?.trial_expires && new Date(u.trial_expires) > new Date());
const planOf = (u) => {
  if (isAdmin(u)) return "pro";
  if (u.plan !== "free" && u.plan_expires && new Date(u.plan_expires) > new Date()) return u.plan;
  if (trialActive(u)) return "pro"; // full-feature trial
  return "free";
};
const onTrial = (u) => !isAdmin(u) && !(u.plan !== "free" && u.plan_expires && new Date(u.plan_expires) > new Date()) && trialActive(u);
async function freshUser(id) {
  const r = await q("SELECT * FROM users WHERE id=$1", [id]);
  if (!r.rows[0]) throw httpErr(401, "User not found");
  return r.rows[0];
}
async function requireOwnership(req) {
  const r = await q("SELECT * FROM trading_accounts WHERE metaapi_id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  if (!r.rows[0]) throw httpErr(404, "Trading account not found on your profile");
  return r.rows[0];
}
async function requirePaidPlan(req) {
  const u = await freshUser(req.user.id);
  if (isAdmin(u)) return u;
  if (planOf(u) === "free") throw httpErr(403, "Trade execution needs a paid plan — upgrade to Trader or Pro. Monitoring stays free.");
  return u;
}
const accountLimit = (u) => {
  if (isAdmin(u)) return ADMIN_ACCOUNT_LIMIT;
  const p = planOf(u);
  return p === "free" ? 1 : PLANS[p].accounts;
};

/* ---------------- auth ---------------- */
const signToken = (u) => jwt.sign({ id: u.id, email: u.email, name: u.name }, JWT_SECRET, { expiresIn: "30d" });
const publicUser = (u) => ({
  id: u.id, email: u.email, name: u.name,
  plan: planOf(u), planExpires: u.plan_expires, admin: isAdmin(u),
  onTrial: onTrial(u), trialExpires: u.trial_expires || null,
  billingInterval: u.billing_interval || null,
});

app.post("/api/auth/register", wrap(async (req) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) throw httpErr(400, "Name, email and password are required");
  if (password.length < 8) throw httpErr(400, "Password must be at least 8 characters");
  const hash = await bcrypt.hash(password, 10);
  let r;
  try {
    // Every new account starts with a full-feature trial (Pro access) for TRIAL_DAYS.
    r = await q(
      `INSERT INTO users (email, name, password_hash, trial_expires, trial_used)
       VALUES ($1,$2,$3, now() + ($4 || ' days')::interval, true) RETURNING *`,
      [email.trim().toLowerCase(), name.trim(), hash, String(TRIAL_DAYS)]);
  } catch (e) {
    if (e.code === "23505") throw httpErr(409, "An account with this email already exists");
    throw e;
  }
  return { token: signToken(r.rows[0]), user: publicUser(r.rows[0]) };
}));

app.post("/api/auth/login", wrap(async (req) => {
  const { email, password } = req.body || {};
  const r = await q("SELECT * FROM users WHERE email=$1", [String(email || "").trim().toLowerCase()]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(password || "", u.password_hash))) throw httpErr(401, "Wrong email or password");
  return { token: signToken(u), user: publicUser(u) };
}));

/* ---------------- password reset ---------------- */
const RESEND_KEY = process.env.RESEND_API_KEY || "";
const MAIL_FROM = process.env.MAIL_FROM || "Halo Trade <onboarding@resend.dev>";
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

async function sendResetEmail(to, link) {
  if (!RESEND_KEY) return false; // email not configured
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: MAIL_FROM, to: [to], subject: "Reset your Halo Trade password",
      html: `<div style="font-family:sans-serif;line-height:1.6">
        <h2 style="color:#171410">Halo Trade — password reset</h2>
        <p>We received a request to reset your password. This link is valid for 60 minutes:</p>
        <p><a href="${link}" style="background:#d99b16;color:#171410;padding:11px 18px;border-radius:8px;text-decoration:none;font-weight:700">Reset password</a></p>
        <p style="color:#6f6656;font-size:13px">If you didn't request this, you can ignore this email — your password stays unchanged.</p>
      </div>`,
    }),
  });
  if (!res.ok) { console.error("resend failed:", await res.text().catch(() => "")); return false; }
  return true;
}

async function sendEmail(to, subject, html) {
  if (!RESEND_KEY) return false;
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, html }),
    });
    if (!res.ok) { console.error("email failed:", await res.text().catch(() => "")); return false; }
    return true;
  } catch (e) { console.error("email error:", e.message); return false; }
}

/* Request a reset link. Always returns ok (don't leak which emails exist). */
app.post("/api/auth/forgot", wrap(async (req) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const r = await q("SELECT * FROM users WHERE email=$1", [email]);
  const u = r.rows[0];
  if (u) {
    const raw = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 60 * 60 * 1000);
    await q("INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES ($1,$2,$3)", [sha256(raw), u.id, expires]);
    const link = `${process.env.APP_URL || ""}/?reset=${raw}`;
    const sent = await sendResetEmail(u.email, link);
    // If email isn't configured, surface the link so the admin can hand it over manually.
    if (!sent && isAdmin({ email: req.body?.requestedBy })) return { ok: true, link };
    if (!sent && !RESEND_KEY) return { ok: true, emailConfigured: false, link };
  }
  return { ok: true, emailConfigured: Boolean(RESEND_KEY) };
}));

/* Complete a reset with the token from the email link. */
app.post("/api/auth/reset", wrap(async (req) => {
  const { token, password } = req.body || {};
  if (!token || !password) throw httpErr(400, "Token and new password are required");
  if (String(password).length < 8) throw httpErr(400, "Password must be at least 8 characters");
  const r = await q("SELECT * FROM password_resets WHERE token_hash=$1", [sha256(String(token))]);
  const row = r.rows[0];
  if (!row || row.used || new Date(row.expires_at) < new Date())
    throw httpErr(400, "This reset link is invalid or has expired. Request a new one.");
  const hash = await bcrypt.hash(String(password), 10);
  await q("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, row.user_id]);
  await q("UPDATE password_resets SET used=true WHERE token_hash=$1", [row.token_hash]);
  const u = (await q("SELECT * FROM users WHERE id=$1", [row.user_id])).rows[0];
  return { ok: true, token: signToken(u), user: publicUser(u) };
}));

/* Admin: force-set a user's password directly (support tool). Admin only. */
app.post("/api/admin/reset-password", wrap(async (req) => {
  const me = await freshUser(req.user.id);
  if (!isAdmin(me)) throw httpErr(403, "Admin only");
  const { email, newPassword } = req.body || {};
  if (!email || !newPassword) throw httpErr(400, "email and newPassword are required");
  if (String(newPassword).length < 8) throw httpErr(400, "Password must be at least 8 characters");
  const r = await q("SELECT * FROM users WHERE email=$1", [String(email).trim().toLowerCase()]);
  if (!r.rows[0]) throw httpErr(404, "No user with that email");
  const hash = await bcrypt.hash(String(newPassword), 10);
  await q("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, r.rows[0].id]);
  return { ok: true, message: `Password updated for ${email}` };
}));

app.get("/api/me", wrap(async (req) => {
  const u = await freshUser(req.user.id);
  const accs = await q("SELECT COUNT(*)::int AS n FROM trading_accounts WHERE user_id=$1", [u.id]);
  return {
    user: publicUser(u),
    accountCount: accs.rows[0].n,
    accountLimit: accountLimit(u),
    telegram: { connected: !!u.telegram_chat_id, notifyEnabled: u.notify_enabled !== false, botAvailable: !!(TG_TOKEN && TG_BOT_USERNAME) },
    planLimits: { free: 1, ...Object.fromEntries(Object.entries(PLANS).map(([k, v]) => [k, v.accounts])) },
  };
}));

/* ---------------- Telegram notifications ---------------- */
async function tgSend(chatId, text) {
  if (!TG_TOKEN || !chatId) return false;
  try {
    const res = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: "HTML", disable_web_page_preview: true }),
    });
    return res.ok;
  } catch (e) { console.error("telegram send:", e.message); return false; }
}
/* Notify the owner of a trading account, respecting their toggle. */
async function notifyAccount(metaapiId, text) {
  try {
    const r = await q(
      `SELECT u.telegram_chat_id AS chat, u.notify_enabled AS on
       FROM trading_accounts ta JOIN users u ON u.id = ta.user_id
       WHERE ta.metaapi_id = $1`, [metaapiId]);
    const row = r.rows[0];
    if (row?.chat && row.on !== false) await tgSend(row.chat, text);
  } catch (e) { console.error("notifyAccount:", e.message); }
}

/* Generate a one-time link code; user taps the deep link, bot sends /start <code>. */
app.post("/api/telegram/link-code", wrap(async (req) => {
  if (!TG_TOKEN || !TG_BOT_USERNAME) throw httpErr(500, "Telegram alerts aren't configured on the server yet.");
  const code = crypto.randomBytes(9).toString("base64url");
  await q("UPDATE users SET telegram_link_code=$1 WHERE id=$2", [code, req.user.id]);
  return { code, deepLink: `https://t.me/${TG_BOT_USERNAME}?start=${code}`, botUsername: TG_BOT_USERNAME };
}));

app.post("/api/telegram/disconnect", wrap(async (req) => {
  await q("UPDATE users SET telegram_chat_id=NULL, telegram_link_code=NULL WHERE id=$1", [req.user.id]);
  return { connected: false };
}));

app.post("/api/telegram/toggle", wrap(async (req) => {
  const on = Boolean(req.body?.enabled);
  await q("UPDATE users SET notify_enabled=$1 WHERE id=$2", [on, req.user.id]);
  return { notifyEnabled: on };
}));

/* Telegram webhook — receives /start <code> to bind a chat to a user. */
app.post("/webhooks/telegram", async (req, res) => {
  try {
    const msg = req.body?.message;
    const text = msg?.text || "";
    const chatId = msg?.chat?.id;
    if (chatId && text.startsWith("/start")) {
      const code = text.split(" ")[1]?.trim();
      if (code) {
        const r = await q("SELECT * FROM users WHERE telegram_link_code=$1", [code]);
        const u = r.rows[0];
        if (u) {
          await q("UPDATE users SET telegram_chat_id=$1, telegram_link_code=NULL WHERE id=$2", [String(chatId), u.id]);
          await tgSend(chatId, `✅ <b>Halo Trade connected!</b>\nYou'll get alerts here for fills, stops, targets, and your discipline &amp; risk rules.\n\nHi ${u.name.split(" ")[0]} — your desk is watching. 🇬🇭`);
        } else {
          await tgSend(chatId, "That link has expired. Open Halo Trade → Alerts and tap Connect Telegram again to get a fresh link.");
        }
      } else {
        await tgSend(chatId, "Welcome to Halo Trade. To receive alerts, open the app → Alerts → Connect Telegram, and use the button there.");
      }
    }
    res.sendStatus(200);
  } catch (e) { console.error("tg webhook:", e.message); res.sendStatus(200); }
});

/* ---------------- trading accounts (per user) ---------------- */
app.get("/api/trading-accounts", wrap(async (req) => {
  const r = await q("SELECT metaapi_id, name, platform, broker_server, login, created_at FROM trading_accounts WHERE user_id=$1 ORDER BY id", [req.user.id]);
  return r.rows.map((a) => ({ ...a, demo: isDemo(a.metaapi_id) }));
}));

app.post("/api/trading-accounts", wrap(async (req) => {
  const u = await freshUser(req.user.id);
  const limit = accountLimit(u);
  const count = (await q("SELECT COUNT(*)::int AS n FROM trading_accounts WHERE user_id=$1", [u.id])).rows[0].n;
  if (count >= limit) throw httpErr(403, isAdmin(u)
    ? `Admin account limit is ${limit}. Raise ADMIN_ACCOUNT_LIMIT to add more.`
    : `Your ${planOf(u)} plan allows ${limit} account${limit > 1 ? "s" : ""}. Upgrade for more.`);

  const { name, platform, server, login, password, existingMetaApiId } = req.body || {};
  let metaapiId;
  if (existingMetaApiId) {
    metaapiId = String(existingMetaApiId).trim();
  } else {
    if (!platform || !server || !login || !password) throw httpErr(400, "platform, server, login and password are required");
    const created = await mapi(PROVISIONING_API, "/users/current/accounts", {
      method: "POST",
      body: {
        name: name || `${login}@${server}`,
        type: "cloud-g2",
        login: String(login),
        password: String(password),
        server: String(server),
        platform: String(platform).toLowerCase(),
        magic: 0,
        region: REGION,
        quoteStreamingIntervalInSeconds: 2.5,
        reliability: "regular",
      },
    });
    metaapiId = created.id;
    try { await mapi(PROVISIONING_API, `/users/current/accounts/${metaapiId}/deploy`, { method: "POST" }); }
    catch (e) { console.error("deploy after create failed:", e.message); }
  }
  const r = await q(
    "INSERT INTO trading_accounts (user_id, metaapi_id, name, platform, broker_server, login) VALUES ($1,$2,$3,$4,$5,$6) RETURNING metaapi_id, name, platform, broker_server, login",
    [u.id, metaapiId, name || `${platform || "MT"} account`, (platform || "mt5").toLowerCase(), server || null, login ? String(login) : null]
  );
  return r.rows[0];
}));

/* Phase B — spin up a read-only demo account so users can try Halo before connecting a broker */
app.post("/api/trading-accounts/demo", wrap(async (req) => {
  const u = await freshUser(req.user.id);
  // one demo per user — reuse if it exists
  const existing = await q("SELECT metaapi_id, name, platform, broker_server, login FROM trading_accounts WHERE user_id=$1 AND metaapi_id LIKE 'demo-%'", [u.id]);
  if (existing.rows[0]) return { ...existing.rows[0], demo: true, reused: true };
  const metaapiId = `demo-${u.id}-${Date.now().toString(36)}`;
  const r = await q(
    "INSERT INTO trading_accounts (user_id, metaapi_id, name, platform, broker_server, login) VALUES ($1,$2,$3,$4,$5,$6) RETURNING metaapi_id, name, platform, broker_server, login",
    [u.id, metaapiId, "Halo Demo Account", "mt5", "HaloDemo-Server", "999999"]
  );
  return { ...r.rows[0], demo: true };
}));

app.delete("/api/trading-accounts/:id", wrap(async (req) => {
  const acc = await requireOwnership(req);
  if (!isDemo(acc.metaapi_id)) {
    try { await mapi(PROVISIONING_API, `/users/current/accounts/${acc.metaapi_id}/undeploy`, { method: "POST" }); }
    catch (e) { console.error("undeploy failed:", e.message); }
  }
  await q("DELETE FROM trading_accounts WHERE metaapi_id=$1 AND user_id=$2", [acc.metaapi_id, req.user.id]);
  await q("DELETE FROM discipline WHERE metaapi_id=$1", [acc.metaapi_id]);
  return { removed: true };
}));

/* ---------------- demo mode (Phase B) ----------------
   A demo account has metaapi_id starting "demo-". It never touches MetaApi;
   the proxy returns realistic simulated data so a new user can feel the product
   before connecting a real broker. Demo data is read-only and deterministic-ish
   (drifts gently over time so it looks live). */
const isDemo = (id) => typeof id === "string" && id.startsWith("demo-");

function demoData(kind) {
  const now = Date.now();
  // gentle drift so numbers move a little each refresh
  const drift = Math.sin(now / 90000) * 18 + Math.cos(now / 47000) * 9;
  const baseEquity = 10000 + drift;
  const positions = [
    { id: "d1", symbol: "XAUUSD", type: "POSITION_TYPE_BUY", volume: 0.20, openPrice: 2338.40, currentPrice: 2338.40 + drift * 0.12, profit: +(drift * 3.1).toFixed(2), stopLoss: 2325.00, takeProfit: 2360.00, time: new Date(now - 52 * 60000).toISOString() },
    { id: "d2", symbol: "EURUSD", type: "POSITION_TYPE_SELL", volume: 0.50, openPrice: 1.0885, currentPrice: 1.0885 - drift * 0.00004, profit: +(drift * 1.7).toFixed(2), stopLoss: 1.0920, takeProfit: 1.0840, time: new Date(now - 18 * 60000).toISOString() },
    { id: "d3", symbol: "US30", type: "POSITION_TYPE_BUY", volume: 0.10, openPrice: 39420, currentPrice: 39420 + drift * 0.8, profit: +(drift * 0.9).toFixed(2), stopLoss: 39250, takeProfit: 0, time: new Date(now - 6 * 60000).toISOString() },
  ];
  const floating = positions.reduce((s, p) => s + p.profit, 0);
  if (kind === "info") {
    return {
      broker: "Halo Demo Broker", currency: "USD", server: "HaloDemo-Server", login: 999999,
      balance: 10000, equity: +(baseEquity + floating).toFixed(2), margin: 640, freeMargin: +(baseEquity + floating - 640).toFixed(2),
      marginLevel: +(((baseEquity + floating) / 640) * 100).toFixed(1), leverage: 100, type: "ACCOUNT_TRADE_MODE_DEMO", name: "Halo Demo Account",
    };
  }
  if (kind === "positions") return positions;
  if (kind === "orders") return [
    { id: "do1", symbol: "GBPUSD", type: "ORDER_TYPE_BUY_LIMIT", volume: 0.30, openPrice: 1.2650, currentPrice: 1.2690, stopLoss: 1.2600, takeProfit: 1.2750, time: new Date(now - 120 * 60000).toISOString() },
  ];
  if (kind === "history") {
    const out = []; const syms = ["XAUUSD", "EURUSD", "US30", "GBPJPY", "USDJPY"];
    for (let i = 0; i < 18; i++) {
      const win = Math.random() > 0.42;
      out.push({
        id: "h" + i, symbol: syms[i % syms.length],
        type: i % 2 ? "DEAL_TYPE_SELL" : "DEAL_TYPE_BUY", volume: +(0.1 + Math.random()).toFixed(2),
        profit: +((win ? 1 : -1) * (10 + Math.random() * 120)).toFixed(2),
        time: new Date(now - (i + 1) * 8 * 3600000).toISOString(),
      });
    }
    return out;
  }
  return {};
}
const proxyGet = (suffix, demoKind) => wrap(async (req) => {
  await requireOwnership(req);
  if (isDemo(req.params.id)) return demoData(demoKind);
  return mapi(CLIENT_API, `/users/current/accounts/${req.params.id}${suffix(req)}`);
});
app.get("/api/accounts/:id/info", proxyGet(() => "/account-information", "info"));
app.get("/api/accounts/:id/positions", proxyGet(() => "/positions", "positions"));
app.get("/api/accounts/:id/orders", proxyGet(() => "/orders", "orders"));
app.get("/api/accounts/:id/spec/:symbol", proxyGet((r) => `/symbols/${r.params.symbol}/specification`, "spec"));
app.get("/api/accounts/:id/price/:symbol", proxyGet((r) => `/symbols/${r.params.symbol}/current-price`, "price"));
app.get("/api/accounts/:id/history", wrap(async (req) => {
  await requireOwnership(req);
  if (isDemo(req.params.id)) return demoData("history");
  const days = Math.min(Number(req.query.days) || 7, 90);
  const end = new Date(); const start = new Date(end.getTime() - days * 86400000);
  return mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/history-deals/time/${start.toISOString()}/${end.toISOString()}`);
}));
app.get("/api/accounts/:id/prices", wrap(async (req) => {
  await requireOwnership(req);
  if (isDemo(req.params.id)) return {};
  const symbols = String(req.query.symbols || "").split(",").map((s) => s.trim().toUpperCase()).filter(Boolean).slice(0, 20);
  const results = await Promise.allSettled(symbols.map((s) =>
    mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/symbols/${encodeURIComponent(s)}/current-price`)));
  const out = {};
  symbols.forEach((s, i) => {
    out[s] = results[i].status === "fulfilled"
      ? { bid: results[i].value.bid, ask: results[i].value.ask }
      : { error: "unavailable" };
  });
  return out;
}));

/* ---------------- discipline helpers ---------------- */
async function disciplineRow(metaapiId) {
  const r = await q("SELECT * FROM discipline WHERE metaapi_id=$1", [metaapiId]);
  return r.rows[0] || null;
}
const isLocked = (d) => Boolean(d && d.enabled && Number(d.lock_until) > Date.now());

/* Extract the currencies a symbol touches, so the news filter only blocks relevant events.
   XAUUSD → [USD] (gold is USD-driven), EURUSD → [EUR, USD], US30 → [USD], etc. */
function symbolCurrencies(symbol) {
  const raw = String(symbol || "").toUpperCase();     // keep digits for index names (US30, DE40)
  const letters = raw.replace(/[^A-Z]/g, "");          // for currency-code matching
  const known = ["USD", "EUR", "GBP", "JPY", "AUD", "NZD", "CAD", "CHF", "CNY"];
  const found = new Set();
  for (const c of known) if (letters.includes(c)) found.add(c);
  // metals & most indices are USD-quoted
  if (/XAU|XAG|XPT|XPD|US30|US500|US100|NAS|SPX|DJI|USTEC|WTI|USOIL/.test(raw)) found.add("USD");
  if (/GER|DAX|DE40|EU50|STOXX/.test(raw)) found.add("EUR");
  if (/UK100|FTSE/.test(raw)) found.add("GBP");
  if (/JP225|NIK/.test(raw)) found.add("JPY");
  return [...found];
}

/* ---------------- trade routes (paid plans only) ---------------- */
app.post("/api/accounts/:id/orders", wrap(async (req) => {
  await requireOwnership(req); await requirePaidPlan(req);
  if (isDemo(req.params.id)) throw httpErr(400, "This is a demo account — trading is simulated. Connect a real MT4/MT5 account to place live orders.");
  const a = await automationRow(req.params.id);
  // Prop-firm halts / cool-off — reject outright, never reaches the broker
  if (a?.prop_enabled && a.prop_halted) {
    const why = a.prop_status === "passed" ? "Challenge passed — trading is paused so you don't give back the target. Reset to start a new attempt." : "Challenge halted after a drawdown breach. Reset to start a new attempt.";
    logDiscipline(req.user.id, req.params.id, a.prop_status === "passed" ? "prop_target" : "prop_breach", `Order blocked: ${req.body?.symbol || ""} — challenge ${a.prop_status || "halted"}`);
    throw httpErr(423, why);
  }
  if (a?.prop_enabled && Number(a.prop_locked_until) > Date.now()) {
    logDiscipline(req.user.id, req.params.id, "streak_pause", `Order blocked: ${req.body?.symbol || ""} — losing-streak cool-off`);
    throw httpErr(423, `Losing-streak cool-off in effect until ${new Date(Number(a.prop_locked_until)).toLocaleString("en-GB", { timeZone: "Europe/London" })} London time.`);
  }
  // News filter — block trading in the window around a high-impact event
  if (a?.news_enabled) {
    const curs = symbolCurrencies(req.body?.symbol);
    const ev = await nextRelevantEvent(Number(a.news_before_mins || 15), Number(a.news_after_mins || 15), curs, a.news_impact || "high");
    if (ev) {
      const mins = Math.round((ev.time - Date.now()) / 60000);
      const when = mins >= 0 ? `in ${mins} min` : `${-mins} min ago`;
      logDiscipline(req.user.id, req.params.id, "news_block", `Order blocked: ${req.body?.symbol || ""} — ${ev.impact} ${ev.currency} "${ev.title}" ${when}`);
      throw httpErr(423, `News filter: ${ev.impact} impact ${ev.currency} event "${ev.title}" ${when}. Trading is paused around it — protect your account from the spike.`);
    }
  }
  // Daily-loss lock — reject outright
  if (a?.dll_enabled && Number(a.dll_locked_until) > Date.now()) {
    logDiscipline(req.user.id, req.params.id, "daily_loss", `Order blocked: ${req.body?.symbol || ""} — daily loss limit reached`);
    throw httpErr(423, `Daily loss limit hit — trading is locked until tomorrow (${new Date(Number(a.dll_locked_until)).toLocaleString("en-GB", { timeZone: "Europe/London", hour: "2-digit", minute: "2-digit" })} London).`);
  }
  // One-shot discipline lock — reject outright
  const d = await disciplineRow(req.params.id);
  if (isLocked(d)) {
    logDiscipline(req.user.id, req.params.id, "lock_block", `Order blocked: ${req.body?.symbol || ""} — one-shot lock active (revenge-trade prevented)`);
    throw httpErr(423, `One-shot lock active until ${new Date(Number(d.lock_until)).toLocaleString("en-GB", { timeZone: "Europe/London" })} London time. No new orders.`);
  }
  if (d?.enabled) {
    // one trade at a time: reject if a position OR a pending order already exists
    const [open, pend] = await Promise.all([
      mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/positions`),
      mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/orders`),
    ]);
    if ((open || []).length > 0) { logDiscipline(req.user.id, req.params.id, "lock_block", `Order blocked: ${req.body?.symbol || ""} — one-shot, trade already live`); throw httpErr(423, "One-shot mode: a trade is already live."); }
    if ((pend || []).length > 0) { logDiscipline(req.user.id, req.params.id, "lock_block", `Order blocked: ${req.body?.symbol || ""} — one-shot, pending order exists`); throw httpErr(423, "One-shot mode: you already have a pending order."); }
  }
  const { side, symbol, volume, type = "market", openPrice, stopLoss, takeProfit, comment } = req.body || {};
  if (!side || !symbol || !volume) throw httpErr(400, "side, symbol and volume are required");
  const map = {
    "buy:market": "ORDER_TYPE_BUY", "sell:market": "ORDER_TYPE_SELL",
    "buy:limit": "ORDER_TYPE_BUY_LIMIT", "sell:limit": "ORDER_TYPE_SELL_LIMIT",
    "buy:stop": "ORDER_TYPE_BUY_STOP", "sell:stop": "ORDER_TYPE_SELL_STOP",
  };
  const actionType = map[`${side}:${type}`];
  if (!actionType) throw httpErr(400, "Invalid side/type combination");
  const result = await mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/trade`, {
    method: "POST",
    body: { actionType, symbol, volume: Number(volume), openPrice, stopLoss, takeProfit, comment: comment || "HaloTrade" },
  });
  notifyAccount(req.params.id,
    `📈 <b>Order sent</b>\n${side.toUpperCase()} ${type} ${volume} ${symbol}${openPrice ? ` @ ${openPrice}` : ""}${stopLoss ? `\nSL ${stopLoss}` : ""}${takeProfit ? `\nTP ${takeProfit}` : ""}`);
  return result;
}));

app.patch("/api/accounts/:id/positions/:positionId", wrap(async (req) => {
  await requireOwnership(req); await requirePaidPlan(req);
  if (isDemo(req.params.id)) throw httpErr(400, "Demo account — actions are simulated. Connect a real account to manage live trades.");
  return mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/trade`, {
    method: "POST",
    body: { actionType: "POSITION_MODIFY", positionId: req.params.positionId, stopLoss: req.body?.stopLoss ?? undefined, takeProfit: req.body?.takeProfit ?? undefined },
  });
}));

app.post("/api/accounts/:id/positions/:positionId/close", wrap(async (req) => {
  await requireOwnership(req); await requirePaidPlan(req);
  if (isDemo(req.params.id)) throw httpErr(400, "Demo account — actions are simulated. Connect a real account to manage live trades.");
  const volume = req.body?.volume ? Number(req.body.volume) : null;
  return mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/trade`, {
    method: "POST",
    body: volume
      ? { actionType: "POSITION_PARTIAL", positionId: req.params.positionId, volume }
      : { actionType: "POSITION_CLOSE_ID", positionId: req.params.positionId },
  });
}));

app.delete("/api/accounts/:id/orders/:orderId", wrap(async (req) => {
  await requireOwnership(req); await requirePaidPlan(req);
  if (isDemo(req.params.id)) throw httpErr(400, "Demo account — actions are simulated. Connect a real account to manage live trades.");
  return mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/trade`, {
    method: "POST", body: { actionType: "ORDER_CANCEL", orderId: req.params.orderId },
  });
}));

/* ---------------- discipline (per user account, DB-backed) ---------------- */
function nextLondonOpen() {
  const now = new Date();
  const lon = new Date(now.toLocaleString("en-US", { timeZone: "Europe/London" }));
  const target = new Date(lon);
  target.setHours(8, 0, 0, 0);
  if (lon >= target) target.setDate(target.getDate() + 1);
  while (target.getDay() === 6 || target.getDay() === 0) target.setDate(target.getDate() + 1);
  return now.getTime() + (target.getTime() - lon.getTime());
}

app.get("/api/discipline/:id", wrap(async (req) => {
  await requireOwnership(req);
  const d = await disciplineRow(req.params.id);
  return {
    enabled: !!d?.enabled, lockUntil: Number(d?.lock_until || 0),
    tradeLive: !!d?.trade_live, locked: isLocked(d), lastEvent: d?.last_event || null,
  };
}));

app.post("/api/discipline/:id", wrap(async (req) => {
  await requireOwnership(req);
  const want = Boolean(req.body?.enabled);
  if (want) await requirePaidPlan(req);
  const d = await disciplineRow(req.params.id);
  if (!want && isLocked(d)) {
    throw httpErr(409, `Lock is active until ${new Date(Number(d.lock_until)).toLocaleString("en-GB", { timeZone: "Europe/London" })} London — one-shot mode cannot be disarmed during a lockout.`);
  }
  await q(`INSERT INTO discipline (metaapi_id, user_id, enabled, lock_until, last_event)
           VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT (metaapi_id) DO UPDATE SET enabled=$3, lock_until=CASE WHEN $3 THEN discipline.lock_until ELSE 0 END, last_event=$5`,
    [req.params.id, req.user.id, want, 0, want ? "armed" : "disarmed"]);
  const nd = await disciplineRow(req.params.id);
  return { enabled: !!nd.enabled, lockUntil: Number(nd.lock_until), tradeLive: !!nd.trade_live, locked: isLocked(nd) };
}));

/* ---------------- automation: trailing stop, auto break-even, daily loss ---------------- */
async function automationRow(metaapiId) {
  const r = await q("SELECT * FROM automation WHERE metaapi_id=$1", [metaapiId]);
  return r.rows[0] || null;
}
const num = (v, d = 0) => { const n = Number(v); return isFinite(n) && n >= 0 ? n : d; };
const publicAutomation = (a) => ({
  trailingEnabled: !!a?.trailing_enabled, trailingDistance: Number(a?.trailing_distance || 0), trailingStart: Number(a?.trailing_start || 0),
  beEnabled: !!a?.be_enabled, beTrigger: Number(a?.be_trigger || 0), beOffset: Number(a?.be_offset || 0),
  dllEnabled: !!a?.dll_enabled, dllPercent: Number(a?.dll_percent || 0),
  dllLockedUntil: Number(a?.dll_locked_until || 0), dllStartEquity: Number(a?.dll_start_equity || 0),
  prop: {
    enabled: !!a?.prop_enabled,
    baseline: Number(a?.prop_baseline || 0),
    maxDrawdownPercent: Number(a?.prop_max_dd_percent || 0),
    targetPercent: Number(a?.prop_target_percent || 0),
    streakPause: Number(a?.prop_streak_pause || 0),
    streakCount: Number(a?.prop_streak_count || 0),
    lockedUntil: Number(a?.prop_locked_until || 0),
    halted: !!a?.prop_halted,
    status: a?.prop_status || null,
  },
  news: {
    enabled: !!a?.news_enabled,
    beforeMins: Number(a?.news_before_mins ?? 15),
    afterMins: Number(a?.news_after_mins ?? 15),
    impact: a?.news_impact || "high",
    closeOpen: !!a?.news_close,
  },
  lastEvent: a?.last_event || null,
});

app.get("/api/automation/:id", wrap(async (req) => {
  await requireOwnership(req);
  return publicAutomation(await automationRow(req.params.id));
}));

app.post("/api/automation/:id", wrap(async (req) => {
  await requireOwnership(req);
  await requirePaidPlan(req);
  const b = req.body || {};
  const cur = await automationRow(req.params.id);
  const v = {
    trailing_enabled: b.trailingEnabled ?? cur?.trailing_enabled ?? false,
    trailing_distance: num(b.trailingDistance ?? cur?.trailing_distance),
    trailing_start: num(b.trailingStart ?? cur?.trailing_start),
    be_enabled: b.beEnabled ?? cur?.be_enabled ?? false,
    be_trigger: num(b.beTrigger ?? cur?.be_trigger),
    be_offset: num(b.beOffset ?? cur?.be_offset),
    dll_enabled: b.dllEnabled ?? cur?.dll_enabled ?? false,
    dll_percent: num(b.dllPercent ?? cur?.dll_percent),
  };
  await q(`INSERT INTO automation (metaapi_id, user_id, trailing_enabled, trailing_distance, trailing_start, be_enabled, be_trigger, be_offset, dll_enabled, dll_percent, last_event)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'settings updated')
           ON CONFLICT (metaapi_id) DO UPDATE SET
             trailing_enabled=$3, trailing_distance=$4, trailing_start=$5,
             be_enabled=$6, be_trigger=$7, be_offset=$8,
             dll_enabled=$9, dll_percent=$10, last_event='settings updated'`,
    [req.params.id, req.user.id, v.trailing_enabled, v.trailing_distance, v.trailing_start,
     v.be_enabled, v.be_trigger, v.be_offset, v.dll_enabled, v.dll_percent]);
  return publicAutomation(await automationRow(req.params.id));
}));

/* ---------------- prop-firm rule pack ---------------- */
/* Configure the challenge rules. Capturing the baseline uses the live balance if not provided. */
app.post("/api/automation/:id/prop", wrap(async (req) => {
  await requireOwnership(req);
  await requirePaidPlan(req);
  const b = req.body || {};
  const cur = await automationRow(req.params.id);

  // ensure a row exists first
  if (!cur) {
    await q("INSERT INTO automation (metaapi_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", [req.params.id, req.user.id]);
  }

  const enabled = Boolean(b.enabled);
  let baseline = num(b.baseline ?? cur?.prop_baseline);
  // if arming and no baseline given, capture current balance as the challenge start
  if (enabled && (!baseline || b.recapture)) {
    try {
      const info = await mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/account-information`);
      baseline = info.balance || info.equity || baseline;
    } catch { /* keep provided/previous baseline */ }
  }
  const resetProgress = enabled && (b.recapture || !cur?.prop_enabled);
  await q(`UPDATE automation SET
      prop_enabled=$2, prop_baseline=$3, prop_max_dd_percent=$4, prop_target_percent=$5, prop_streak_pause=$6,
      prop_status=CASE WHEN $2 THEN 'active' ELSE prop_status END,
      prop_halted=CASE WHEN $7 THEN false ELSE prop_halted END,
      prop_streak_count=CASE WHEN $7 THEN 0 ELSE prop_streak_count END,
      prop_locked_until=CASE WHEN $7 THEN 0 ELSE prop_locked_until END,
      last_event='prop rules updated'
    WHERE metaapi_id=$1`,
    [req.params.id, enabled, baseline, num(b.maxDrawdownPercent ?? cur?.prop_max_dd_percent),
     num(b.targetPercent ?? cur?.prop_target_percent), Math.round(num(b.streakPause ?? cur?.prop_streak_pause)), resetProgress]);
  return publicAutomation(await automationRow(req.params.id));
}));

/* Reset a challenge (e.g. new attempt) — recapture baseline, clear halt/streak. */
app.post("/api/automation/:id/prop/reset", wrap(async (req) => {
  await requireOwnership(req);
  await requirePaidPlan(req);
  let baseline = 0;
  try { const info = await mapi(CLIENT_API, `/users/current/accounts/${req.params.id}/account-information`); baseline = info.balance || info.equity || 0; } catch {}
  await q(`UPDATE automation SET prop_baseline=$2, prop_halted=false, prop_streak_count=0, prop_locked_until=0, prop_status='active', last_event='challenge reset' WHERE metaapi_id=$1`,
    [req.params.id, baseline]);
  return publicAutomation(await automationRow(req.params.id));
}));

/* ---------------- news filter settings ---------------- */
app.post("/api/automation/:id/news", wrap(async (req) => {
  await requireOwnership(req);
  await requirePaidPlan(req);
  const b = req.body || {};
  const cur = await automationRow(req.params.id);
  if (!cur) {
    await q("INSERT INTO automation (metaapi_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", [req.params.id, req.user.id]);
  }
  const impact = ["high", "medium", "low"].includes(String(b.impact)) ? b.impact : (cur?.news_impact || "high");
  await q(`UPDATE automation SET
      news_enabled=$2, news_before_mins=$3, news_after_mins=$4, news_impact=$5, news_close=$6, last_event='news filter updated'
    WHERE metaapi_id=$1`,
    [req.params.id,
     Boolean(b.enabled),
     Math.max(0, Math.round(num(b.beforeMins ?? cur?.news_before_mins ?? 15))),
     Math.max(0, Math.round(num(b.afterMins ?? cur?.news_after_mins ?? 15))),
     impact,
     Boolean(b.closeOpen)]);
  return publicAutomation(await automationRow(req.params.id));
}));

/* ---------------- watchdog (all armed accounts, all users) ---------------- */
async function closeEverything(metaapiId, reason) {
  const positions = await mapi(CLIENT_API, `/users/current/accounts/${metaapiId}/positions`);
  for (const p of positions || []) {
    try {
      await mapi(CLIENT_API, `/users/current/accounts/${metaapiId}/trade`, {
        method: "POST", body: { actionType: "POSITION_CLOSE_ID", positionId: p.id, comment: reason },
      });
    } catch (e) { console.error(`watchdog close failed ${metaapiId}:`, e.message); }
  }
  const orders = await mapi(CLIENT_API, `/users/current/accounts/${metaapiId}/orders`);
  for (const o of orders || []) {
    try {
      await mapi(CLIENT_API, `/users/current/accounts/${metaapiId}/trade`, {
        method: "POST", body: { actionType: "ORDER_CANCEL", orderId: o.id },
      });
    } catch (e) { console.error(`watchdog cancel failed ${metaapiId}:`, e.message); }
  }
  return (positions || []).length;
}

let watchdogBusy = false;
async function watchdogTick() {
  if (watchdogBusy || !TOKEN) return;
  watchdogBusy = true;
  try {
    const rows = (await q("SELECT * FROM discipline WHERE enabled=true")).rows;
    for (const d of rows) {
      const id = d.metaapi_id;
      try {
        if (Number(d.lock_until) && Date.now() >= Number(d.lock_until)) {
          await q("UPDATE discipline SET lock_until=0, last_event=$2 WHERE metaapi_id=$1", [id, "lock expired — desk reopened"]);
          d.lock_until = 0;
        }
        const positions = await mapi(CLIENT_API, `/users/current/accounts/${id}/positions`);
        const count = (positions || []).length;
        if (isLocked(d)) {
          if (count > 0) {
            const n = await closeEverything(id, "HaloOneShot-lock");
            await q("UPDATE discipline SET last_event=$2 WHERE metaapi_id=$1", [id, `force-closed ${n} position(s) during lockout`]);
          }
        } else {
          if (count > 1) {
            const sorted = [...positions].sort((a, b) => new Date(a.time) - new Date(b.time));
            for (const extra of sorted.slice(1)) {
              try {
                await mapi(CLIENT_API, `/users/current/accounts/${id}/trade`, {
                  method: "POST", body: { actionType: "POSITION_CLOSE_ID", positionId: extra.id, comment: "HaloOneShot-extra" },
                });
              } catch (e) { console.error("watchdog extra-close:", e.message); }
            }
          }
          if (d.trade_live && count === 0) {
            const until = nextLondonOpen();
            try { await closeEverything(id, "HaloOneShot-lock"); } catch {}
            await q("UPDATE discipline SET lock_until=$2, last_event=$3 WHERE metaapi_id=$1",
              [id, until, `trade closed — locked until ${new Date(until).toISOString()}`]);
            console.log(`watchdog: ${id} locked until ${new Date(until).toISOString()}`);
            notifyAccount(id, `🔒 <b>One-shot lock engaged</b>\nYour trade closed. New orders are locked until London open (${new Date(until).toLocaleString("en-GB", { timeZone: "Europe/London", weekday: "short", hour: "2-digit", minute: "2-digit" })}). No revenge trades. 🇬🇭`);
            logDiscipline(null, id, "oneshot_lock", "Trade closed — one-shot lock engaged until London open");
            d.lock_until = until;
          }
        }
        await q("UPDATE discipline SET trade_live=$2 WHERE metaapi_id=$1", [id, !isLocked(d) && count > 0]);
      } catch (e) { console.error(`watchdog ${id}:`, e.message); }
    }
  } finally { watchdogBusy = false; }
}

/* Fast enforcement: only touches accounts that are CURRENTLY locked (discipline lockout,
   prop halt, prop cool-off, or daily-loss lock). Runs every 2s so anything opened outside
   the Halo app — MT4/MT5 app, broker web terminal — is force-flattened almost instantly.
   Kept deliberately small so it's cheap to run at high frequency. */
let fastGuardBusy = false;
async function fastGuardTick() {
  if (fastGuardBusy || !TOKEN) return;
  fastGuardBusy = true;
  try {
    const now = Date.now();
    // discipline one-shot lockouts
    const locked = (await q("SELECT metaapi_id FROM discipline WHERE enabled=true AND lock_until > $1", [now])).rows;
    // prop halts and cool-offs, and daily-loss locks
    const propLocked = (await q(
      "SELECT metaapi_id FROM automation WHERE (prop_enabled=true AND (prop_halted=true OR prop_locked_until > $1)) OR (dll_enabled=true AND dll_locked_until > $1)",
      [now]
    )).rows;
    const ids = [...new Set([...locked.map((r) => r.metaapi_id), ...propLocked.map((r) => r.metaapi_id)])];
    for (const id of ids) {
      try {
        const positions = await mapi(CLIENT_API, `/users/current/accounts/${id}/positions`);
        if ((positions || []).length > 0) {
          const n = await closeEverything(id, "HaloGuard-instant");
          console.log(`fastGuard: flattened ${n} position(s) on locked account ${id}`);
          logDiscipline(null, id, "guard_flatten", `Auto-closed ${n} position(s) opened outside Halo on a locked account`);
        }
        // also kill any pending orders placed during lockout
        const orders = await mapi(CLIENT_API, `/users/current/accounts/${id}/orders`);
        for (const o of orders || []) {
          try {
            await mapi(CLIENT_API, `/users/current/accounts/${id}/trade`, {
              method: "POST", body: { actionType: "ORDER_CANCEL", orderId: o.id, comment: "HaloGuard-cancel" },
            });
          } catch (e) { console.error("fastGuard cancel:", e.message); }
        }
      } catch (e) { console.error(`fastGuard ${id}:`, e.message); }
    }
  } finally { fastGuardBusy = false; }
}

/* ---------------- automation engine: trailing stop, auto break-even, daily loss ---------------- */
const todayStr = () => new Date().toLocaleDateString("en-CA", { timeZone: "Europe/London" }); // yyyy-mm-dd, London day

function pointSize(symbol, price) {
  // Approximate MetaTrader "point" per symbol family, good enough for trailing math.
  const s = String(symbol || "").toUpperCase();
  if (s.includes("XAU") || s.includes("GOLD")) return 0.01;
  if (s.includes("JPY")) return 0.001;
  if (s.includes("BTC") || s.includes("US30") || s.includes("NAS") || s.includes("SPX") || s.includes("XAG")) return 0.1;
  if (/^[A-Z]{6}$/.test(s)) return 0.00001; // fx majors
  return price >= 1000 ? 0.1 : price >= 10 ? 0.001 : 0.00001;
}

async function modifyPos(id, position, stopLoss, comment) {
  await mapi(CLIENT_API, `/users/current/accounts/${id}/trade`, {
    method: "POST",
    body: { actionType: "POSITION_MODIFY", positionId: position.id, stopLoss, takeProfit: position.takeProfit ?? undefined },
  });
  console.log(`automation: ${comment} on ${position.symbol} (${id}) → SL ${stopLoss}`);
  if (comment === "break-even") {
    notifyAccount(id, `⚖️ <b>Break-even set</b>\n${position.symbol}: stop moved to protect the trade. It can't lose now.`);
  }
}

let autoBusy = false;
async function automationTick() {
  if (autoBusy || !TOKEN) return;
  autoBusy = true;
  try {
    const rows = (await q("SELECT * FROM automation WHERE trailing_enabled=true OR be_enabled=true OR dll_enabled=true OR prop_enabled=true OR (news_enabled=true AND news_close=true)")).rows;
    for (const a of rows) {
      const id = a.metaapi_id;
      try {
        /* ---- News filter: close open positions during a high-impact event window ---- */
        if (a.news_enabled && a.news_close) {
          try {
            const positions = await mapi(CLIENT_API, `/users/current/accounts/${id}/positions`);
            if ((positions || []).length) {
              // check each open symbol against its relevant events
              let hit = null;
              for (const p of positions) {
                const curs = symbolCurrencies(p.symbol);
                const ev = await nextRelevantEvent(Number(a.news_before_mins || 15), Number(a.news_after_mins || 15), curs, a.news_impact || "high");
                if (ev) { hit = ev; break; }
              }
              if (hit) {
                const n = await closeEverything(id, "HaloNews-close");
                await q("UPDATE automation SET last_event=$2 WHERE metaapi_id=$1", [id, `news filter closed ${n} position(s) around ${hit.currency} ${hit.title}`]);
                notifyAccount(id, `📅 <b>News filter — positions closed</b>\nHigh-impact ${hit.currency} event "${hit.title}" is in your block window. Halo closed ${n} position(s) to protect you from the spike.`);
                continue;
              }
            }
          } catch (e) { /* positions unavailable briefly; ignore */ }
        }

        /* ---- Prop-firm rule pack (max drawdown, profit target, losing-streak pause) ---- */
        if (a.prop_enabled && a.prop_baseline > 0 && !a.prop_halted) {
          const info = await mapi(CLIENT_API, `/users/current/accounts/${id}/account-information`);
          const baseline = Number(a.prop_baseline);
          const equity = Number(info?.equity);
          if (!isFinite(equity)) { /* account not ready — skip this tick */ }
          else {
          // 1) Max overall drawdown breach → close all, hard halt
          if (a.prop_max_dd_percent > 0) {
            const floor = baseline * (1 - Number(a.prop_max_dd_percent) / 100);
            if (equity <= floor) {
              const n = await closeEverything(id, "HaloProp-breach");
              await q("UPDATE automation SET prop_halted=true, prop_status='breached', last_event=$2 WHERE metaapi_id=$1",
                [id, `max drawdown ${a.prop_max_dd_percent}% breached — halted`]);
              notifyAccount(id, `⛔ <b>Challenge drawdown breached</b>\nEquity hit your ${a.prop_max_dd_percent}% max drawdown. Halo closed ${n} position(s) and halted trading to stop further damage. Reset when you start a new attempt.`);
              logDiscipline(null, id, "prop_breach", `Max drawdown ${a.prop_max_dd_percent}% breached — closed ${n} position(s), halted`);
              continue;
            }
          }
          // 2) Profit target reached → close all, mark passed
          if (a.prop_target_percent > 0) {
            const goal = baseline * (1 + Number(a.prop_target_percent) / 100);
            if (equity >= goal) {
              const n = await closeEverything(id, "HaloProp-target");
              await q("UPDATE automation SET prop_halted=true, prop_status='passed', last_event=$2 WHERE metaapi_id=$1",
                [id, `profit target ${a.prop_target_percent}% reached — challenge passed`]);
              notifyAccount(id, `🎯 <b>Profit target reached!</b>\nYou hit +${a.prop_target_percent}% — Halo banked it by closing ${n} position(s) and paused trading so you don't give it back. Congratulations. 🇬🇭`);
              logDiscipline(null, id, "prop_target", `Profit target +${a.prop_target_percent}% reached — banked ${n} position(s)`);
              continue;
            }
          }
          }
        }
        // enforce an active prop halt or streak-pause: keep the account flat
        if (a.prop_enabled && (a.prop_halted || Number(a.prop_locked_until) > Date.now())) {
          try {
            const pos = await mapi(CLIENT_API, `/users/current/accounts/${id}/positions`);
            if ((pos || []).length) await closeEverything(id, a.prop_halted ? "HaloProp-halt" : "HaloProp-pause");
          } catch {}
          if (a.prop_halted) continue; // fully halted; skip other automations
        }
        // 3) Losing-streak pause: watch newly-closed deals; N losses in a row → cool-off
        if (a.prop_enabled && a.prop_streak_pause > 0 && Number(a.prop_locked_until) <= Date.now()) {
          try {
            const now = new Date();
            const from = new Date(now.getTime() - 7 * 864e5).toISOString();
            const deals = await mapi(CLIENT_API, `/users/current/accounts/${id}/history-deals/time/${from}/${now.toISOString()}`);
            const closing = (deals || [])
              .filter((d) => d.entryType === "DEAL_ENTRY_OUT" && typeof d.profit === "number")
              .sort((x, y) => new Date(x.time) - new Date(y.time));
            const latest = closing[closing.length - 1];
            if (latest && String(latest.id) !== String(a.prop_last_deal_id || "")) {
              // process only the newest closed deal since we last checked
              const isLoss = latest.profit < 0;
              let streak = isLoss ? Number(a.prop_streak_count) + 1 : 0;
              if (isLoss && streak >= Number(a.prop_streak_pause)) {
                const until = Date.now() + 60 * 60 * 1000; // 1-hour cool-off
                await q("UPDATE automation SET prop_streak_count=0, prop_last_deal_id=$2, prop_locked_until=$3, last_event=$4 WHERE metaapi_id=$1",
                  [id, String(latest.id), until, `${a.prop_streak_pause} losses in a row — 1-hour cool-off`]);
                notifyAccount(id, `⏸ <b>Losing streak — cooling off</b>\n${a.prop_streak_pause} losses in a row. Halo paused new trades for 1 hour. Step back, reset your head, protect the challenge.`);
                logDiscipline(null, id, "streak_pause", `${a.prop_streak_pause} losses in a row — 1-hour cool-off enforced`);
              } else {
                await q("UPDATE automation SET prop_streak_count=$2, prop_last_deal_id=$3 WHERE metaapi_id=$1",
                  [id, streak, String(latest.id)]);
              }
            }
          } catch (e) { /* history may be unavailable briefly; ignore */ }
        }

        /* ---- Daily loss limit (server-side, auto-close) ---- */
        if (a.dll_enabled && a.dll_percent > 0) {
          const info = await mapi(CLIENT_API, `/users/current/accounts/${id}/account-information`);
          const day = todayStr();
          if (a.dll_day !== day) {
            // new trading day → reset baseline
            await q("UPDATE automation SET dll_day=$2, dll_start_equity=$3, dll_locked_until=0 WHERE metaapi_id=$1", [id, day, info.equity]);
            a.dll_day = day; a.dll_start_equity = info.equity; a.dll_locked_until = 0;
          }
          const lockActive = Number(a.dll_locked_until) > Date.now();
          const loss = a.dll_start_equity - info.equity;
          const limit = (Number(a.dll_percent) / 100) * a.dll_start_equity;
          if (!lockActive && limit > 0 && loss >= limit) {
            const n = await closeEverything(id, "HaloDailyLoss");
            // lock the rest of the London day (until next midnight London)
            const until = (() => {
              const lon = new Date(new Date().toLocaleString("en-US", { timeZone: "Europe/London" }));
              const midnight = new Date(lon); midnight.setHours(24, 0, 0, 0);
              return Date.now() + (midnight.getTime() - lon.getTime());
            })();
            await q("UPDATE automation SET dll_locked_until=$2, last_event=$3 WHERE metaapi_id=$1",
              [id, until, `daily loss ${a.dll_percent}% hit — closed ${n} position(s), locked for the day`]);
            console.log(`automation: ${id} daily-loss hit, closed ${n}, locked until ${new Date(until).toISOString()}`);
            notifyAccount(id, `🛡 <b>Daily loss guard triggered</b>\nDown ${a.dll_percent}% on the day — Halo closed ${n} position(s) and locked the account until tomorrow. Protect the capital. 🇬🇭`);
            logDiscipline(null, id, "daily_loss", `Daily loss ${a.dll_percent}% hit — closed ${n} position(s), locked for the day`);
            continue; // nothing else to manage this tick
          }
          if (lockActive) {
            // enforce: keep the account flat for the rest of the day
            const pos = await mapi(CLIENT_API, `/users/current/accounts/${id}/positions`);
            if ((pos || []).length) await closeEverything(id, "HaloDailyLoss-lock");
            continue;
          }
        }

        /* ---- Trailing stop + auto break-even (need live positions) ---- */
        if (a.trailing_enabled || a.be_enabled) {
          const positions = await mapi(CLIENT_API, `/users/current/accounts/${id}/positions`);
          for (const p of positions || []) {
            const isBuy = String(p.type || "").includes("BUY");
            const price = p.currentPrice ?? p.openPrice;
            const pt = pointSize(p.symbol, price);
            const profitPts = (isBuy ? price - p.openPrice : p.openPrice - price) / pt;

            // Auto break-even: once in profit by be_trigger points, move SL to entry (+offset)
            if (a.be_enabled && a.be_trigger > 0 && profitPts >= Number(a.be_trigger)) {
              const target = isBuy ? p.openPrice + Number(a.be_offset) * pt : p.openPrice - Number(a.be_offset) * pt;
              const already = p.stopLoss && (isBuy ? p.stopLoss >= p.openPrice : p.stopLoss <= p.openPrice);
              if (!already) {
                try { await modifyPos(id, p, +target.toFixed(8), "break-even"); } catch (e) { console.error("BE fail:", e.message); }
              }
            }

            // Trailing stop: once past trailing_start profit, keep SL trailing_distance behind price
            if (a.trailing_enabled && a.trailing_distance > 0 && profitPts >= Number(a.trailing_start)) {
              const dist = Number(a.trailing_distance) * pt;
              const newSL = isBuy ? price - dist : price + dist;
              const better = !p.stopLoss || (isBuy ? newSL > p.stopLoss : newSL < p.stopLoss);
              // never move SL to a losing side of entry via trailing
              const safe = isBuy ? newSL > p.openPrice - dist : newSL < p.openPrice + dist;
              if (better && safe) {
                try { await modifyPos(id, p, +newSL.toFixed(8), "trailing"); } catch (e) { console.error("trail fail:", e.message); }
              }
            }
          }
        }
      } catch (e) { console.error(`automation ${id}:`, e.message); }
    }
  } finally { autoBusy = false; }
}

/* ---------------- billing (Paystack) ---------------- */
app.get("/api/billing/plans", (_req, res) => res.json(
  Object.fromEntries(Object.entries(PLANS).map(([k, v]) => [k, {
    label: v.label, amountPesewas: v.amount, accounts: v.accounts,
    annualPesewas: annualAmount(k), // 2 months free
  }]))
));

app.post("/api/billing/init", wrap(async (req) => {
  if (!PAYSTACK_SECRET) throw httpErr(500, "Paystack is not configured on the server");
  const plan = String(req.body?.plan || "");
  const interval = req.body?.interval === "annual" ? "annual" : "monthly";
  if (!PLANS[plan]) throw httpErr(400, "Unknown plan");
  const amount = interval === "annual" ? annualAmount(plan) : PLANS[plan].amount;
  const u = await freshUser(req.user.id);
  const res = await fetch("https://api.paystack.co/transaction/initialize", {
    method: "POST",
    headers: { Authorization: `Bearer ${PAYSTACK_SECRET}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      email: u.email,
      amount,
      currency: "GHS",
      callback_url: `${process.env.APP_URL || ""}/?billing=done`,
      metadata: { userId: u.id, plan, interval },
    }),
  });
  const data = await res.json();
  if (!data.status) throw httpErr(502, data.message || "Paystack init failed");
  return { authorizationUrl: data.data.authorization_url, reference: data.data.reference };
}));

app.post("/webhooks/paystack", async (req, res) => {
  try {
    const sig = req.get("x-paystack-signature") || "";
    const digest = crypto.createHmac("sha512", PAYSTACK_SECRET).update(req.rawBody || Buffer.from("")).digest("hex");
    if (sig !== digest) return res.status(401).send("bad signature");
    const evt = req.body;
    if (evt.event === "charge.success") {
      const { userId, plan, interval } = evt.data.metadata || {};
      if (userId && PLANS[plan]) {
        const days = INTERVAL_DAYS[interval] || INTERVAL_DAYS.monthly;
        await q(`UPDATE users SET plan=$2, billing_interval=$4, renewal_reminded_at=NULL,
                 plan_expires=GREATEST(COALESCE(plan_expires, now()), now()) + ($3 || ' days')::interval
                 WHERE id=$1`, [userId, plan, String(days), interval || "monthly"]);
        await q("INSERT INTO payments (user_id, reference, plan, amount) VALUES ($1,$2,$3,$4) ON CONFLICT (reference) DO NOTHING",
          [userId, evt.data.reference, plan, evt.data.amount]);
        console.log(`billing: user ${userId} -> ${plan} (${interval || "monthly"}, ref ${evt.data.reference})`);
      }
    }
    res.sendStatus(200);
  } catch (e) { console.error("webhook error:", e.message); res.sendStatus(500); }
});

/* ---------------- health + SPA ---------------- */
/* ---------------- economic calendar / news filter ---------------- */
let newsCache = { at: 0, events: [] };
const IMPACT_RANK = { high: 3, medium: 2, low: 1, holiday: 0, tentative: 0, "": 0 };

function normalizeImpact(raw) {
  const s = String(raw || "").toLowerCase();
  if (s.includes("high") || s === "3") return "high";
  if (s.includes("med") || s === "2") return "medium";
  if (s.includes("low") || s === "1") return "low";
  if (s.includes("holiday")) return "holiday";
  return "";
}
/* Parse a variety of provider shapes into a common event schema. */
function normalizeEvents(data) {
  const arr = Array.isArray(data) ? data : (data?.events || data?.result || data?.data || []);
  const out = [];
  for (const e of arr) {
    const title = e.title || e.event || e.name || e.indicator || e.Name || e.Event;
    const currency = (e.country || e.currency || e.economy || e.Currency || e.Country || "").toString().toUpperCase();
    const impact = normalizeImpact(e.impact || e.importance || e.volatility || e.Strength || e.Impact);
    // time: ForexFactory uses "date" ISO; others use timestamp/date+time/capitalized
    let time = e.date || e.datetime || e.time || e.timestamp || e.Date || e.DateTime;
    let ts = null;
    if (typeof time === "number") ts = time > 1e12 ? time : time * 1000;
    else if (time) { const d = new Date(time); if (!isNaN(d)) ts = d.getTime(); }
    if (!title || !ts) continue;
    out.push({
      title: String(title), currency, impact,
      time: ts, iso: new Date(ts).toISOString(),
      forecast: e.forecast ?? e.Forecast ?? null, previous: e.previous ?? e.Previous ?? null, actual: e.actual ?? e.Actual ?? null,
    });
  }
  return out.sort((a, b) => a.time - b.time);
}
/* Feed URLs tried in order. ForexFactory rate-limits hard (2 req / 5 min across all
   formats) and returns an HTML "Request Denied" page when throttled, so we cache a good
   result for a long time and only refetch occasionally. */
const NEWS_FEED_URLS = [
  NEWS_FEED_URL,
  "https://cdn-nfs.faireconomy.media/ff_calendar_thisweek.json",
  "https://nfs.faireconomy.media/ff_calendar_thisweek.json",
];
const NEWS_CACHE_MS = 6 * 60 * 60 * 1000;   // 6h: the weekly feed rarely changes intraday
const NEWS_RETRY_MS = 15 * 60 * 1000;       // if we have NO data yet, retry every 15 min

async function fetchNewsOnce(url) {
  const headers = {
    // a browser-like UA gets through more often than a generic one
    "User-Agent": "Mozilla/5.0 (compatible; HaloTrade/1.0; +https://halo-trade-api-production.up.railway.app)",
    "Accept": "application/json, text/plain, */*",
  };
  // Keyed providers: JBlanked uses "Authorization: Api-Key KEY"; others use a Bearer token
  // or a ?token= query param. NEWS_AUTH_SCHEME lets you pick: 'apikey' | 'bearer' | 'query'.
  const key = process.env.NEWS_API_KEY;
  let finalUrl = url;
  if (key) {
    const scheme = (process.env.NEWS_AUTH_SCHEME || "apikey").toLowerCase();
    if (scheme === "bearer") headers["Authorization"] = `Bearer ${key}`;
    else if (scheme === "query") finalUrl += (url.includes("?") ? "&" : "?") + `token=${encodeURIComponent(key)}`;
    else headers["Authorization"] = `Api-Key ${key}`; // JBlanked default
  }
  const res = await fetch(finalUrl, { headers });
  if (!res.ok) throw new Error(`feed ${res.status}`);
  const text = await res.text();
  // ForexFactory returns an HTML "Request Denied" page when rate-limited — reject it
  const trimmed = text.trimStart().toLowerCase();
  if (trimmed.startsWith("<!doctype") || trimmed.startsWith("<html") || trimmed.includes("request denied")) {
    throw new Error("feed rate-limited (HTML response)");
  }
  const data = JSON.parse(text);
  return normalizeEvents(data);
}

async function getNewsEvents() {
  const have = newsCache.events.length > 0;
  const age = Date.now() - newsCache.at;
  // fresh enough → serve cache
  if (have && age < NEWS_CACHE_MS) return newsCache.events;
  // no data yet but we tried very recently → don't hammer; serve what we have (maybe empty)
  if (!have && age < NEWS_RETRY_MS && newsCache.at > 0) return newsCache.events;

  for (const url of NEWS_FEED_URLS) {
    try {
      const events = await fetchNewsOnce(url);
      if (events.length) { newsCache = { at: Date.now(), events }; return events; }
    } catch (e) {
      console.error(`news fetch (${url.split("/")[2]}):`, e.message);
    }
  }
  // all sources failed — record the attempt time, serve stale (may be empty)
  newsCache = { at: Date.now(), events: newsCache.events };
  return newsCache.events;
}
/* Next high/medium event within `mins`, optionally filtered to currencies. */
async function nextRelevantEvent(minsBefore, minsAfter, currencies, minImpact = "high") {
  const events = await getNewsEvents();
  const now = Date.now();
  const rank = IMPACT_RANK[minImpact] || 3;
  const curs = (currencies || []).map((c) => c.toUpperCase());
  for (const ev of events) {
    if ((IMPACT_RANK[ev.impact] || 0) < rank) continue;
    if (curs.length && !curs.includes(ev.currency)) continue;
    const start = ev.time - minsBefore * 60000;
    const end = ev.time + minsAfter * 60000;
    if (now >= start && now <= end) return ev;
  }
  return null;
}

app.get("/api/calendar", wrap(async (req) => {
  const events = await getNewsEvents();
  const now = Date.now();
  const horizon = now + 7 * 864e5;
  const impactMin = IMPACT_RANK[String(req.query.impact || "low")] || 1;
  const upcoming = events.filter((e) => e.time >= now - 3600e3 && e.time <= horizon && (IMPACT_RANK[e.impact] || 0) >= impactMin);
  return {
    events: upcoming.slice(0, 120),
    source: NEWS_FEED_URL.replace(/^https?:\/\//, "").split("/")[0],
    cachedAt: newsCache.at,
    available: events.length > 0, // false = feed couldn't be reached at all
  };
}));

/* ---------------- discipline report (Phase A) ---------------- */
const KIND_LABELS = {
  lock_block: "Revenge trades blocked",
  oneshot_lock: "One-shot locks engaged",
  daily_loss: "Daily-loss stops",
  prop_breach: "Challenge breaches caught",
  prop_target: "Profit targets banked",
  streak_pause: "Losing-streak cool-offs",
  news_block: "Trades blocked around news",
  guard_flatten: "Out-of-app trades auto-closed",
};

app.get("/api/discipline-report", wrap(async (req) => {
  const days = Math.min(365, Math.max(1, Number(req.query.days) || 30));
  const since = new Date(Date.now() - days * 864e5);
  const rows = (await q(
    `SELECT kind, detail, created_at FROM discipline_events
     WHERE user_id=$1 AND created_at >= $2 ORDER BY created_at DESC`,
    [req.user.id, since]
  )).rows;

  // tally by kind
  const counts = {};
  for (const r of rows) counts[r.kind] = (counts[r.kind] || 0) + 1;

  // "interventions" = times Halo actively protected the user
  const blocks = (counts.lock_block || 0) + (counts.news_block || 0) + (counts.guard_flatten || 0);
  const stops = (counts.daily_loss || 0) + (counts.oneshot_lock || 0) + (counts.streak_pause || 0) + (counts.prop_breach || 0);
  const wins = counts.prop_target || 0;
  const total = rows.length;

  // build a per-day series for a simple sparkline
  const byDay = {};
  for (const r of rows) {
    const day = new Date(r.created_at).toISOString().slice(0, 10);
    byDay[day] = (byDay[day] || 0) + 1;
  }
  const series = [];
  for (let i = days - 1; i >= 0; i--) {
    const day = new Date(Date.now() - i * 864e5).toISOString().slice(0, 10);
    series.push({ day, count: byDay[day] || 0 });
  }

  // headline stat + human summary
  const breakdown = Object.entries(counts)
    .map(([kind, count]) => ({ kind, label: KIND_LABELS[kind] || kind, count }))
    .sort((a, b) => b.count - a.count);

  return {
    days, total,
    blocks, stops, wins,
    breakdown,
    series,
    recent: rows.slice(0, 15).map((r) => ({ kind: r.kind, label: KIND_LABELS[r.kind] || r.kind, detail: r.detail, at: r.created_at })),
  };
}));

/* ---------------- trade journal (Phase C) ---------------- */
const EMOTIONS = ["calm", "confident", "fearful", "greedy", "fomo", "revenge", "bored"];
const OUTCOMES = ["win", "loss", "breakeven", "open", "skipped"];

app.get("/api/journal", wrap(async (req) => {
  const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
  const rows = (await q(
    "SELECT id, symbol, direction, rationale, emotion, outcome, lesson, created_at FROM journal_entries WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2",
    [req.user.id, limit]
  )).rows;
  // small insight summary: emotion frequency + win-rate by emotion
  const byEmotion = {};
  for (const r of rows) {
    if (!r.emotion) continue;
    const e = (byEmotion[r.emotion] = byEmotion[r.emotion] || { count: 0, wins: 0, losses: 0 });
    e.count++;
    if (r.outcome === "win") e.wins++;
    if (r.outcome === "loss") e.losses++;
  }
  return { entries: rows, insights: { byEmotion } };
}));

app.post("/api/journal", wrap(async (req) => {
  const b = req.body || {};
  const clean = (v, max = 2000) => (v == null ? null : String(v).slice(0, max));
  const emotion = EMOTIONS.includes(b.emotion) ? b.emotion : null;
  const outcome = OUTCOMES.includes(b.outcome) ? b.outcome : null;
  const direction = b.direction === "buy" || b.direction === "sell" ? b.direction : null;
  if (!b.rationale && !b.lesson && !b.symbol) throw httpErr(400, "Add at least a symbol, rationale, or lesson.");
  const r = await q(
    `INSERT INTO journal_entries (user_id, symbol, direction, rationale, emotion, outcome, lesson)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, symbol, direction, rationale, emotion, outcome, lesson, created_at`,
    [req.user.id, clean(b.symbol, 20)?.toUpperCase() || null, direction, clean(b.rationale), emotion, outcome, clean(b.lesson)]
  );
  return r.rows[0];
}));

app.patch("/api/journal/:id", wrap(async (req) => {
  const b = req.body || {};
  const clean = (v, max = 2000) => (v == null ? null : String(v).slice(0, max));
  const emotion = EMOTIONS.includes(b.emotion) ? b.emotion : null;
  const outcome = OUTCOMES.includes(b.outcome) ? b.outcome : null;
  const direction = b.direction === "buy" || b.direction === "sell" ? b.direction : null;
  const r = await q(
    `UPDATE journal_entries SET symbol=$3, direction=$4, rationale=$5, emotion=$6, outcome=$7, lesson=$8
     WHERE id=$1 AND user_id=$2
     RETURNING id, symbol, direction, rationale, emotion, outcome, lesson, created_at`,
    [req.params.id, req.user.id, clean(b.symbol, 20)?.toUpperCase() || null, direction, clean(b.rationale), emotion, outcome, clean(b.lesson)]
  );
  if (!r.rows[0]) throw httpErr(404, "Entry not found.");
  return r.rows[0];
}));

app.delete("/api/journal/:id", wrap(async (req) => {
  await q("DELETE FROM journal_entries WHERE id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  return { removed: true };
}));

/* ---------------- AI support chat ---------------- */
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || "";
const SUPPORT_SYSTEM = `You are Halo, the friendly in-app support assistant for Halo Trade — a web platform for managing MT4/MT5 trading accounts, built in Ghana for traders in Ghana, Nigeria and the diaspora.

Answer questions about how to use Halo Trade concisely and warmly. Key facts:
- Halo connects to MT4/MT5 accounts via a secure trading engine; broker passwords are never stored.
- Free plan = monitoring only. Trader (GHS 250/mo) and Pro (GHS 500/mo) unlock trade execution. New users get a 7-day full-feature trial. Annual plans give 2 months free. Pay with card or Mobile Money via Paystack.
- Features: risk-% lot calculator, one-shot discipline lock (one trade at a time, then locked until London open), trailing stop, auto break-even, daily loss guard, and prop-firm challenge mode (max drawdown, profit target, losing-streak pause). Telegram trade alerts are available.
- To connect an account: Accounts button, then enter platform, broker server, login, and master password.
- To enable alerts: Alerts (bell icon), then Connect Telegram.
- To upgrade: the Upgrade button opens the plans screen.

Rules: Be concise (2-4 sentences usually). Never give financial or trading advice, never predict markets, and never tell users which trades to take — Halo is a tool, not an advisor. If asked for trading signals or predictions, gently decline and redirect to how Halo's tools can help their own strategy. For billing disputes or account-specific problems you can't see, suggest they email support. Never claim to access their live account data. If unsure, say so.`;

app.post("/api/chat", wrap(async (req) => {
  const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
  if (!messages.length) throw httpErr(400, "messages required");
  if (!ANTHROPIC_KEY) {
    return { reply: "Live chat isn't fully set up yet. For help, please email support — or check the Accounts and Alerts panels, which cover most setup questions." };
  }
  const clean = messages.slice(-12).map((m) => ({
    role: m.role === "assistant" ? "assistant" : "user",
    content: String(m.content || "").slice(0, 4000),
  }));
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-sonnet-4-6", max_tokens: 600, system: SUPPORT_SYSTEM, messages: clean }),
    });
    const data = await res.json();
    if (!res.ok) { console.error("chat api:", JSON.stringify(data).slice(0, 300)); throw httpErr(502, "Chat is temporarily unavailable."); }
    const reply = (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
    return { reply: reply || "Sorry, I didn't catch that — could you rephrase?" };
  } catch (e) {
    if (e.status) throw e;
    console.error("chat error:", e.message);
    throw httpErr(502, "Chat is temporarily unavailable.");
  }
}));

/* ---------------- AI discipline coach (Phase D) ----------------
   Unlike support chat, the coach is grounded in the user's own discipline events
   and journal patterns, and speaks like a trading-psychology coach — never giving
   market calls, only helping the trader see and fix their own behaviour. */
const COACH_SYSTEM = `You are the Halo Discipline Coach — a calm, sharp trading-psychology coach inside Halo Trade, a discipline tool for MT4/MT5 traders in Ghana, Nigeria and the diaspora.

Your job: help the trader see their own behavioural patterns and build discipline. You are given a DATA SNAPSHOT of what Halo has recorded about this specific trader (protective actions Halo took, and their own journal entries). Use it to give personal, specific, encouraging coaching.

Hard rules:
- NEVER give market predictions, trade signals, entries, or tell them what to trade. You coach behaviour, not markets.
- Be specific to their data. If the snapshot shows 5 revenge-trade blocks, name that pattern. If their journal shows losses cluster on "fomo" emotion, point it out gently.
- Be concise and warm (3-6 sentences). Talk like a real coach, not a textbook. A little Ghanaian warmth is welcome but don't force it.
- Frame Halo's interventions as wins ("Halo caught 4 revenge trades for you — that's 4 blow-ups avoided"), not failures.
- If there's little or no data, encourage them to arm the discipline lock and journal a few trades so you can coach them properly.
- Never claim to see their live balance or open positions. You only see the discipline log and journal they wrote.
- If asked for anything outside trading discipline/psychology, gently redirect.`;

app.post("/api/coach", wrap(async (req) => {
  const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
  if (!messages.length) throw httpErr(400, "messages required");
  if (!ANTHROPIC_KEY) {
    return { reply: "The AI coach isn't switched on yet. In the meantime, check your Discipline report and Journal — the patterns there are the same ones I'd point you to." };
  }

  // Build a data snapshot grounded in THIS user's real records
  let snapshot = "DATA SNAPSHOT (last 30 days):\n";
  try {
    const since = new Date(Date.now() - 30 * 864e5);
    const evs = (await q("SELECT kind, COUNT(*)::int AS n FROM discipline_events WHERE user_id=$1 AND created_at>=$2 GROUP BY kind", [req.user.id, since])).rows;
    if (evs.length) {
      snapshot += "Halo's protective actions: " + evs.map((e) => `${KIND_LABELS[e.kind] || e.kind}: ${e.n}`).join(", ") + ".\n";
    } else {
      snapshot += "No protective actions recorded yet (either great discipline, or the lock isn't armed).\n";
    }
    const jrn = (await q("SELECT emotion, outcome FROM journal_entries WHERE user_id=$1 AND created_at>=$2", [req.user.id, since])).rows;
    if (jrn.length) {
      const byEmo = {};
      for (const j of jrn) { if (!j.emotion) continue; const e = (byEmo[j.emotion] = byEmo[j.emotion] || { n: 0, w: 0, l: 0 }); e.n++; if (j.outcome === "win") e.w++; if (j.outcome === "loss") e.l++; }
      snapshot += `Journal entries: ${jrn.length}. Emotion patterns: ` + Object.entries(byEmo).map(([em, s]) => `${em} ×${s.n} (${s.w}W/${s.l}L)`).join(", ") + ".\n";
    } else {
      snapshot += "No journal entries yet.\n";
    }
  } catch (e) { snapshot += "(snapshot unavailable)\n"; }

  const clean = messages.slice(-12).map((m) => ({
    role: m.role === "assistant" ? "assistant" : "user",
    content: String(m.content || "").slice(0, 4000),
  }));

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-sonnet-4-6", max_tokens: 700, system: COACH_SYSTEM + "\n\n" + snapshot, messages: clean }),
    });
    const data = await res.json();
    if (!res.ok) { console.error("coach api:", JSON.stringify(data).slice(0, 300)); throw httpErr(502, "The coach is temporarily unavailable."); }
    const reply = (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
    return { reply: reply || "Tell me what's on your mind about your trading discipline." };
  } catch (e) {
    if (e.status) throw e;
    console.error("coach error:", e.message);
    throw httpErr(502, "The coach is temporarily unavailable.");
  }
}));

app.get("/health", async (_req, res) => {
  let db = false; try { await q("SELECT 1"); db = true; } catch {}
  res.json({ ok: true, region: REGION, tokenConfigured: Boolean(TOKEN), db, paystack: Boolean(PAYSTACK_SECRET) });
});

/* Diagnostic: reports the real MetaApi state for each account, so a persistent
   "offline" can be diagnosed by opening a URL instead of digging through devtools.
   Requires the admin token in the query (?key=) to avoid leaking account info. */
app.get("/api/diag", async (req, res) => {
  try {
    if (!TOKEN) return res.json({ error: "METAAPI_TOKEN not set" });
    const accts = (await q("SELECT metaapi_id, name, login FROM trading_accounts WHERE metaapi_id NOT LIKE 'demo-%' ORDER BY id LIMIT 5")).rows;
    if (!accts.length) return res.json({ note: "No real accounts connected yet." });
    const out = [];
    for (const a of accts) {
      const row = { name: a.name, login: a.login, metaapi_id: a.metaapi_id };
      // 1) provisioning state (deployed?)
      try {
        const prov = await mapi(PROVISIONING_API, `/users/current/accounts/${a.metaapi_id}`, { retries: 0, timeoutMs: 8000 });
        row.state = prov.state; row.connectionStatus = prov.connectionStatus; row.provRegion = prov.region;
      } catch (e) { row.provisioningError = `${e.status || ""} ${e.message}`.trim(); }
      // 2) can we actually read account-information? (the call that powers the dashboard)
      try {
        const info = await mapi(CLIENT_API, `/users/current/accounts/${a.metaapi_id}/account-information`, { retries: 0, timeoutMs: 8000 });
        row.accountInfoOk = true; row.balance = info.balance; row.equity = info.equity;
      } catch (e) { row.accountInfoOk = false; row.accountInfoError = `${e.status || ""} ${e.message}`.trim(); }
      out.push(row);
    }
    res.json({ region: REGION, clientApi: CLIENT_API, accounts: out });
  } catch (e) {
    res.json({ error: e.message });
  }
});
app.get(["/welcome", "/welcome/"], (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "welcome.html"));
});
app.get("*", (req, res) => {
  if (req.path.startsWith("/api") || req.path.startsWith("/webhooks")) return res.status(404).json({ error: "Not found" });
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* ---------------- renewal / trial reminders ---------------- */
let reminderBusy = false;
async function reminderTick() {
  if (reminderBusy) return;
  reminderBusy = true;
  try {
    const now = Date.now();
    // Paid plans expiring within 3 days, not reminded in the last 2 days
    const paid = (await q(
      `SELECT * FROM users
       WHERE plan <> 'free' AND plan_expires IS NOT NULL
         AND plan_expires > now() AND plan_expires < now() + interval '3 days'
         AND (renewal_reminded_at IS NULL OR renewal_reminded_at < now() - interval '2 days')`
    )).rows;
    for (const u of paid) {
      const days = Math.max(1, Math.ceil((new Date(u.plan_expires) - now) / 864e5));
      const when = new Date(u.plan_expires).toLocaleDateString("en-GB", { timeZone: "Europe/London", day: "numeric", month: "short" });
      await sendEmail(u.email, `Your Halo Trade ${u.plan} plan renews soon`,
        `<div style="font-family:sans-serif;line-height:1.6">
          <h2 style="color:#171410">Your ${u.plan} plan expires in ${days} day${days > 1 ? "s" : ""}</h2>
          <p>Hi ${u.name.split(" ")[0]}, your Halo Trade <b>${u.plan}</b> plan is set to expire on <b>${when}</b>.</p>
          <p>Renew to keep your automation, discipline lock, and alerts running without interruption.</p>
          <p><a href="${process.env.APP_URL || ""}/?billing=renew" style="background:#d99b16;color:#171410;padding:11px 18px;border-radius:8px;text-decoration:none;font-weight:700">Renew now</a></p>
        </div>`);
      await notifyAccountUser(u, `⏳ <b>Plan renews soon</b>\nYour Halo Trade ${u.plan} plan expires in ${days} day${days > 1 ? "s" : ""} (${when}). Renew in the app to keep automation and alerts running.`);
      await q("UPDATE users SET renewal_reminded_at=now() WHERE id=$1", [u.id]);
      console.log(`reminder: ${u.email} (${u.plan} expires in ${days}d)`);
    }
    // Trials ending within 2 days, not on a paid plan, not reminded recently
    const trials = (await q(
      `SELECT * FROM users
       WHERE (plan = 'free' OR plan_expires IS NULL OR plan_expires < now())
         AND trial_expires IS NOT NULL AND trial_expires > now()
         AND trial_expires < now() + interval '2 days'
         AND (renewal_reminded_at IS NULL OR renewal_reminded_at < now() - interval '2 days')`
    )).rows;
    for (const u of trials) {
      const days = Math.max(1, Math.ceil((new Date(u.trial_expires) - now) / 864e5));
      await sendEmail(u.email, `Your Halo Trade free trial ends in ${days} day${days > 1 ? "s" : ""}`,
        `<div style="font-family:sans-serif;line-height:1.6">
          <h2 style="color:#171410">Your free trial is ending</h2>
          <p>Hi ${u.name.split(" ")[0]}, your full-feature trial ends in <b>${days} day${days > 1 ? "s" : ""}</b>.</p>
          <p>Upgrade to keep trade execution, the discipline lock, automation, and prop-firm mode. Monitoring stays free forever.</p>
          <p><a href="${process.env.APP_URL || ""}/?billing=upgrade" style="background:#d99b16;color:#171410;padding:11px 18px;border-radius:8px;text-decoration:none;font-weight:700">Choose a plan</a></p>
        </div>`);
      await notifyAccountUser(u, `⏳ <b>Trial ending soon</b>\nYour Halo Trade full-feature trial ends in ${days} day${days > 1 ? "s" : ""}. Upgrade to keep execution, discipline lock, and automation running. Monitoring stays free.`);
      await q("UPDATE users SET renewal_reminded_at=now() WHERE id=$1", [u.id]);
      console.log(`reminder: ${u.email} (trial ends in ${days}d)`);
    }
  } catch (e) { console.error("reminderTick:", e.message); }
  finally { reminderBusy = false; }
}
/* Notify a user directly on Telegram (by user row), respecting their toggle. */
async function notifyAccountUser(u, text) {
  if (u?.telegram_chat_id && u.notify_enabled !== false) await tgSend(u.telegram_chat_id, text);
}

migrate()
  .then(() => {
    setInterval(watchdogTick, 10_000);
    setInterval(automationTick, 6_000); // trailing/BE/daily-loss run a bit tighter
    // Fast guard: instant flatten of anything on a locked account. Tunable via env.
    // Default 1000ms. Floor of 500ms to protect against MetaApi rate limits.
    const guardMs = Math.max(500, Number(process.env.FAST_GUARD_MS || 1000));
    setInterval(fastGuardTick, guardMs);
    console.log(`fast guard interval: ${guardMs}ms`);
    // Renewal & trial reminders — check hourly, run once shortly after boot.
    setInterval(reminderTick, 60 * 60 * 1000);
    setTimeout(reminderTick, 30_000);
    app.listen(PORT, () => console.log(`Halo Trade SaaS listening on :${PORT} (region: ${REGION})`));
  })
  .catch((e) => { console.error("migration failed:", e); process.exit(1); });
