// Private Chat: a two-way private messaging site on a single Cloudflare Worker + D1.
// Bindings required: DB (D1 database). Secret required: ADMIN_PASSWORD.

const SESSION_COOKIE = '__Host-sid';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const PBKDF2_ITERATIONS = 100000; // Cloudflare Workers allows at most 100000
const MAX_MESSAGE_LENGTH = 4000;
const MAX_JSON_BYTES = 16384;
const USERNAME_RE = /^[A-Za-z0-9_]{3,30}$/;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const enc = new TextEncoder();

const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN (\'user\', \'admin\')), created_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL, expires_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, sender_role TEXT NOT NULL CHECK (sender_role IN (\'user\', \'admin\')), body TEXT NOT NULL, created_at INTEGER NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)',
  'CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)',
  'CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id, id)',
  'CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)'
];

let schemaReady = null;
function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = env.DB.batch(SCHEMA.map((sql) => env.DB.prepare(sql))).catch((err) => {
      schemaReady = null;
      throw err;
    });
  }
  return schemaReady;
}

/* ---------- byte helpers ---------- */

function bytesToB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Bytes(str) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(str)));
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/* ---------- password hashing (PBKDF2-SHA-256) ---------- */

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations },
    key,
    256
  );
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return 'pbkdf2_sha256$' + PBKDF2_ITERATIONS + '$' + bytesToB64(salt) + '$' + bytesToB64(hash);
}

async function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2_sha256') return false;
  const iterations = parseInt(parts[1], 10);
  if (!(iterations >= 1 && iterations <= 100000)) return false;
  let salt, expected;
  try {
    salt = b64ToBytes(parts[2]);
    expected = b64ToBytes(parts[3]);
  } catch (e) {
    return false;
  }
  const actual = await pbkdf2(password, salt, iterations);
  return constantTimeEqual(actual, expected);
}

// Used so that login for a non-existent username takes about as long as a real one.
let dummyHashPromise = null;
function getDummyHash() {
  if (!dummyHashPromise) dummyHashPromise = hashPassword('dummy-password-for-timing');
  return dummyHashPromise;
}

/* ---------- HTTP helpers ---------- */

const BASE_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
};

function json(data, status, extraHeaders) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign(
      {},
      BASE_HEADERS,
      { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
      extraHeaders || {}
    )
  });
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie');
  if (!header) return null;
  const parts = header.split(';');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    const idx = p.indexOf('=');
    if (idx < 0) continue;
    if (p.slice(0, idx).trim() === name) return p.slice(idx + 1).trim();
  }
  return null;
}

function sessionCookie(token) {
  return SESSION_COOKIE + '=' + token + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000);
}

function clearCookie() {
  return SESSION_COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0';
}

function checkOrigin(request, url) {
  const origin = request.headers.get('Origin');
  if (origin && origin !== url.origin) throw new HttpError(403, 'Cross-origin request blocked.');
  const site = request.headers.get('Sec-Fetch-Site');
  if (site && site !== 'same-origin' && site !== 'none') throw new HttpError(403, 'Cross-site request blocked.');
}

async function readJson(request) {
  const type = request.headers.get('Content-Type') || '';
  if (type.indexOf('application/json') === -1) throw new HttpError(415, 'Content-Type must be application/json.');
  const text = await request.text();
  if (text.length > MAX_JSON_BYTES) throw new HttpError(413, 'Request body too large.');
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new HttpError(400, 'Invalid JSON.');
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new HttpError(400, 'Invalid JSON body.');
  return data;
}

/* ---------- sessions ---------- */

async function createSession(env, userId, role) {
  const token = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = bytesToHex(await sha256Bytes(token));
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?1').bind(now),
    env.DB.prepare('INSERT INTO sessions (token, user_id, role, expires_at) VALUES (?1, ?2, ?3, ?4)').bind(
      tokenHash,
      userId,
      role,
      now + SESSION_TTL_MS
    )
  ]);
  return token;
}

async function getSession(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const tokenHash = bytesToHex(await sha256Bytes(token));
  const row = await env.DB.prepare(
    'SELECT s.token AS token, s.expires_at AS expires_at, u.id AS user_id, u.username AS username, u.role AS role ' +
      'FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?1'
  )
    .bind(tokenHash)
    .first();
  if (!row) return null;
  if (row.expires_at <= Date.now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?1').bind(tokenHash).run();
    return null;
  }
  return row;
}

async function requireRole(request, env, role) {
  const session = await getSession(request, env);
  if (!session) throw new HttpError(401, 'Please log in.');
  if (session.role !== role) throw new HttpError(403, 'Not allowed.');
  return session;
}

/* ---------- validation ---------- */

function cleanMessageBody(value) {
  if (typeof value !== 'string') throw new HttpError(400, 'Message must be text.');
  const body = value.trim();
  if (body.length === 0) throw new HttpError(400, 'Message cannot be empty.');
  if (body.length > MAX_MESSAGE_LENGTH) throw new HttpError(400, 'Message is longer than ' + MAX_MESSAGE_LENGTH + ' characters.');
  return body;
}

/* ---------- API handlers ---------- */

async function handleRegister(request, env) {
  const body = await readJson(request);
  const username = typeof body.username === 'string' ? body.username.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!USERNAME_RE.test(username)) {
    throw new HttpError(400, 'Username must be 3-30 characters: letters, numbers and underscore only.');
  }
  if (password.length < 8) throw new HttpError(400, 'Password must be at least 8 characters.');
  if (password.length > 128) throw new HttpError(400, 'Password must be at most 128 characters.');
  if (username.toLowerCase() === 'admin') throw new HttpError(409, 'That username is not available.');

  const passwordHash = await hashPassword(password);
  let result;
  try {
    result = await env.DB.prepare("INSERT INTO users (username, password_hash, role, created_at) VALUES (?1, ?2, 'user', ?3)")
      .bind(username, passwordHash, Date.now())
      .run();
  } catch (err) {
    if (String(err && err.message).indexOf('UNIQUE') !== -1) throw new HttpError(409, 'That username is not available.');
    throw err;
  }
  const userId = result.meta.last_row_id;
  const token = await createSession(env, userId, 'user');
  return json({ user: { username: username, role: 'user' } }, 201, { 'Set-Cookie': sessionCookie(token) });
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  const username = typeof body.username === 'string' ? body.username.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!username || !password || username.length > 30 || password.length > 256) {
    throw new HttpError(400, 'Enter your username and password.');
  }

  let userId;
  let role;
  let shownName;

  if (username.toLowerCase() === 'admin') {
    const adminPassword = env.ADMIN_PASSWORD;
    if (typeof adminPassword !== 'string' || adminPassword.length === 0) {
      throw new HttpError(500, 'The ADMIN_PASSWORD secret is not configured on this Worker.');
    }
    const ok = constantTimeEqual(await sha256Bytes(password), await sha256Bytes(adminPassword));
    if (!ok) throw new HttpError(401, 'Wrong username or password.');
    // The admin row only exists so sessions have a user_id. Its hash is not a valid
    // PBKDF2 hash, so it can never be used to log in through the normal user path.
    await env.DB.prepare("INSERT OR IGNORE INTO users (username, password_hash, role, created_at) VALUES ('admin', '!', 'admin', ?1)")
      .bind(Date.now())
      .run();
    const row = await env.DB.prepare("SELECT id FROM users WHERE username = 'admin' AND role = 'admin'").first();
    if (!row) throw new HttpError(500, 'Could not initialise the administrator account.');
    userId = row.id;
    role = 'admin';
    shownName = 'admin';
  } else {
    const row = await env.DB.prepare("SELECT id, username, password_hash FROM users WHERE username = ?1 AND role = 'user'")
      .bind(username)
      .first();
    const stored = row ? row.password_hash : await getDummyHash();
    const ok = await verifyPassword(password, stored);
    if (!row || !ok) throw new HttpError(401, 'Wrong username or password.');
    userId = row.id;
    role = 'user';
    shownName = row.username;
  }

  const token = await createSession(env, userId, role);
  return json({ user: { username: shownName, role: role } }, 200, { 'Set-Cookie': sessionCookie(token) });
}

async function handleLogout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token && /^[a-f0-9]{64}$/.test(token)) {
    const tokenHash = bytesToHex(await sha256Bytes(token));
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?1').bind(tokenHash).run();
  }
  return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}

async function handleMe(request, env) {
  const session = await getSession(request, env);
  if (!session) throw new HttpError(401, 'Please log in.');
  return json({ user: { username: session.username, role: session.role } });
}

function parseAfter(url) {
  const n = Number(url.searchParams.get('after'));
  return Number.isSafeInteger(n) && n > 0 ? n : 0;
}

async function fetchMessages(env, userId, after) {
  const res = await env.DB.prepare(
    'SELECT id, user_id, sender_role, body, created_at FROM (' +
      'SELECT id, user_id, sender_role, body, created_at FROM messages WHERE user_id = ?1 AND id > ?2 ORDER BY id DESC LIMIT 500' +
      ') ORDER BY id ASC'
  )
    .bind(userId, after)
    .all();
  return res.results || [];
}

async function insertMessage(env, userId, senderRole, body) {
  const now = Date.now();
  const result = await env.DB.prepare('INSERT INTO messages (user_id, sender_role, body, created_at) VALUES (?1, ?2, ?3, ?4)')
    .bind(userId, senderRole, body, now)
    .run();
  return { id: result.meta.last_row_id, user_id: userId, sender_role: senderRole, body: body, created_at: now };
}

async function handleGetMessages(request, env, url) {
  const session = await requireRole(request, env, 'user');
  // The user id always comes from the session, never from the request.
  const messages = await fetchMessages(env, session.user_id, parseAfter(url));
  return json({ messages: messages });
}

async function handlePostMessage(request, env) {
  const session = await requireRole(request, env, 'user');
  const data = await readJson(request);
  const body = cleanMessageBody(data.body);

  const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM messages WHERE user_id = ?1 AND sender_role = 'user' AND created_at > ?2")
    .bind(session.user_id, Date.now() - 60000)
    .first();
  if (recent && recent.n >= 20) throw new HttpError(429, 'You are sending messages too fast. Wait a moment.');

  const message = await insertMessage(env, session.user_id, 'user', body);
  return json({ message: message }, 201);
}

async function handleAdminUsers(request, env) {
  await requireRole(request, env, 'admin');
  const res = await env.DB.prepare(
    'SELECT u.id AS id, u.username AS username, u.created_at AS created_at, ' +
      '(SELECT COUNT(*) FROM messages m WHERE m.user_id = u.id) AS message_count, ' +
      '(SELECT MAX(m.created_at) FROM messages m WHERE m.user_id = u.id) AS last_message_at, ' +
      '(SELECT m.sender_role FROM messages m WHERE m.user_id = u.id ORDER BY m.id DESC LIMIT 1) AS last_sender ' +
      "FROM users u WHERE u.role = 'user' " +
      'ORDER BY COALESCE((SELECT MAX(m.created_at) FROM messages m WHERE m.user_id = u.id), u.created_at) DESC LIMIT 1000'
  ).all();
  return json({ users: res.results || [] });
}

async function findChatUser(env, userId) {
  return env.DB.prepare("SELECT id, username FROM users WHERE id = ?1 AND role = 'user'").bind(userId).first();
}

async function handleAdminGetMessages(request, env, url) {
  await requireRole(request, env, 'admin');
  const userId = Number(url.searchParams.get('user_id'));
  if (!Number.isSafeInteger(userId) || userId <= 0) throw new HttpError(400, 'A valid user_id is required.');
  const user = await findChatUser(env, userId);
  if (!user) throw new HttpError(404, 'User not found.');
  const messages = await fetchMessages(env, userId, parseAfter(url));
  return json({ user: { id: user.id, username: user.username }, messages: messages });
}

async function handleAdminPostMessage(request, env) {
  await requireRole(request, env, 'admin');
  const data = await readJson(request);
  const userId = data.user_id;
  if (!Number.isSafeInteger(userId) || userId <= 0) throw new HttpError(400, 'A valid user_id is required.');
  const body = cleanMessageBody(data.body);
  const user = await findChatUser(env, userId);
  if (!user) throw new HttpError(404, 'User not found.');
  const message = await insertMessage(env, userId, 'admin', body);
  return json({ message: message }, 201);
}

/* ---------- routing ---------- */

async function route(request, env) {
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname;

  if (path === '/' || path === '/index.html') {
    if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'Method not allowed.');
    return htmlResponse(method === 'HEAD');
  }
  if (path === '/favicon.ico') return new Response(null, { status: 204, headers: BASE_HEADERS });
  if (path.indexOf('/api/') !== 0) throw new HttpError(404, 'Not found.');

  if (!env.DB) throw new HttpError(500, 'The D1 binding named DB is missing on this Worker.');
  if (method !== 'GET') checkOrigin(request, url);
  await ensureSchema(env);

  switch (method + ' ' + path) {
    case 'POST /api/register':
      return handleRegister(request, env);
    case 'POST /api/login':
      return handleLogin(request, env);
    case 'POST /api/logout':
      return handleLogout(request, env);
    case 'GET /api/me':
      return handleMe(request, env);
    case 'GET /api/messages':
      return handleGetMessages(request, env, url);
    case 'POST /api/messages':
      return handlePostMessage(request, env);
    case 'GET /api/admin/users':
      return handleAdminUsers(request, env);
    case 'GET /api/admin/messages':
      return handleAdminGetMessages(request, env, url);
    case 'POST /api/admin/messages':
      return handleAdminPostMessage(request, env);
    default:
      throw new HttpError(404, 'Not found.');
  }
}

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      console.error('Unhandled error:', err && err.stack ? err.stack : err);
      return json({ error: 'Internal server error.' }, 500);
    }
  }
};

/* ---------- frontend ---------- */

function htmlResponse(headOnly) {
  const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const csp =
    "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; " +
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
  return new Response(headOnly ? null : PAGE.split('__NONCE__').join(nonce), {
    status: 200,
    headers: Object.assign({}, BASE_HEADERS, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': csp
    })
  });
}

// NOTE: this template literal must not contain backticks, backslashes or dollar-brace sequences.
const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#050506">
<title>Hello</title>
<style nonce="__NONCE__">
:root{--bg:#050506;--surface:#0f0f11;--raised:#18181b;--line:#27272c;--text:#ececee;--muted:#8d8d96;--faint:#5b5b63;--mine:#ececee;--mine-text:#0a0a0b;--danger:#ff8f86}
*{box-sizing:border-box}
html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font:16px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-text-size-adjust:100%}
[hidden]{display:none!important}
button,input,textarea{font:inherit;color:inherit}
:focus-visible{outline:2px solid #fff;outline-offset:2px}
.app{height:100vh;height:100dvh;display:flex;flex-direction:column;max-width:760px;margin:0 auto;padding:env(safe-area-inset-top) 16px env(safe-area-inset-bottom)}
.app.wide{max-width:1180px}
.hero{padding:28px 0 18px;font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif}
.hero h1{margin:0;font-weight:400;line-height:1.08}
.hero span{display:block;font-size:clamp(2.3rem,10vw,3.9rem);letter-spacing:-.01em}
.hero .l1{color:var(--text)}
.hero .l2{color:var(--muted)}
.hero .l3{color:var(--faint)}
.app.chatting .hero{padding:14px 0 8px}
.app.chatting .hero span{font-size:1.15rem;letter-spacing:0}
.view{flex:1;min-height:0;display:flex;flex-direction:column}
.card{background:var(--surface);border:1px solid var(--line);border-radius:22px;padding:22px;margin-top:6px}
.card h2{margin:0 0 14px;font-size:1.1rem;font-weight:600}
label{display:block;font-size:.88rem;color:var(--muted);margin:12px 0 6px}
input[type=text],input[type=password]{width:100%;min-height:46px;padding:10px 14px;font-size:16px;background:var(--bg);border:1px solid var(--line);border-radius:14px}
.hint{font-size:.82rem;color:var(--faint);margin:6px 0 0}
.error{min-height:1.3em;margin:12px 0 0;color:var(--danger);font-size:.92rem}
.btn{min-height:46px;padding:0 22px;border:0;border-radius:23px;background:var(--mine);color:var(--mine-text);font-weight:600;cursor:pointer}
.btn:disabled{opacity:.5;cursor:default}
.btn.block{width:100%;margin-top:6px}
.btn.ghost{background:transparent;color:var(--muted);border:1px solid var(--line);font-weight:500;min-height:38px;padding:0 16px}
.link{background:none;border:0;padding:12px 0 0;color:var(--muted);text-decoration:underline;cursor:pointer;font-size:.92rem}
.bar{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0}
.bar h2{margin:0;font-family:"Iowan Old Style","Palatino Linotype",Georgia,serif;font-weight:400;font-size:1.6rem}
.who{color:var(--muted);font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.thread{flex:1;min-height:0;overflow-y:auto;display:flex;flex-direction:column;gap:8px;padding:12px 0;overscroll-behavior:contain}
.msg{max-width:82%;padding:9px 14px;border-radius:19px}
.msg .text{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}
.msg .time{font-size:.72rem;opacity:.6;margin-top:3px}
.msg.mine{align-self:flex-end;background:var(--mine);color:var(--mine-text);border-bottom-right-radius:6px}
.msg.theirs{align-self:flex-start;background:var(--raised);border-bottom-left-radius:6px}
.empty{margin:auto;color:var(--faint);text-align:center;padding:0 24px}
.composer{display:flex;gap:8px;align-items:flex-end;padding:10px 0 12px;border-top:1px solid var(--line)}
.composer textarea{flex:1;resize:none;min-height:46px;max-height:140px;padding:11px 16px;font-size:16px;line-height:1.35;background:var(--surface);border:1px solid var(--line);border-radius:23px}
.formerror{min-height:0;margin:0;padding:0 4px;color:var(--danger);font-size:.88rem}
.admin{flex:1;min-height:0;display:grid;grid-template-columns:minmax(0,1fr);grid-template-rows:auto minmax(0,1fr);gap:12px}
.userlist{max-height:28vh;max-height:28dvh;overflow-y:auto;display:flex;flex-direction:column;gap:6px;overscroll-behavior:contain}
.uitem{display:flex;justify-content:space-between;align-items:center;gap:10px;width:100%;text-align:left;padding:10px 14px;background:var(--surface);border:1px solid var(--line);border-radius:14px;cursor:pointer}
.uitem[aria-current=true]{background:var(--raised);border-color:#4a4a52}
.uitem .n{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.uitem .s{display:block;font-size:.76rem;color:var(--faint);font-weight:400}
.badge{flex:none;font-size:.72rem;padding:2px 9px;border-radius:99px;background:var(--mine);color:var(--mine-text);font-weight:600}
.convo{min-height:0;display:flex;flex-direction:column;border:1px solid var(--line);border-radius:18px;padding:0 14px;background:var(--bg)}
.convo h3{margin:0;padding:12px 0 8px;font-size:1rem;border-bottom:1px solid var(--line)}
@media (min-width:800px){
  .admin{grid-template-columns:290px minmax(0,1fr);grid-template-rows:minmax(0,1fr)}
  .userlist{max-height:none}
}
@media (prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
</style>
</head>
<body>
<div id="app" class="app">
  <header id="hero" class="hero" hidden>
    <h1><span class="l1">Hello</span><span class="l2">I'm there</span><span class="l3">Say something</span></h1>
  </header>

  <div id="loadingView" class="view"></div>

  <section id="authView" class="view" hidden>
    <form id="authForm" class="card" novalidate>
      <h2 id="authTitle">Log in</h2>
      <label for="authUser">Username</label>
      <input id="authUser" type="text" name="username" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="30">
      <label for="authPass">Password</label>
      <input id="authPass" type="password" name="password" autocomplete="current-password" maxlength="128">
      <p id="authHint" class="hint" hidden>3-30 characters: letters, numbers and underscore. Password: at least 8 characters.</p>
      <p id="authError" class="error" role="alert"></p>
      <button id="authSubmit" class="btn block" type="submit">Log in</button>
      <button id="authSwitch" class="link" type="button">Create an account</button>
    </form>
  </section>

  <section id="userView" class="view" hidden>
    <div class="bar">
      <span id="userName" class="who"></span>
      <button id="userLogout" class="btn ghost" type="button">Log out</button>
    </div>
    <div id="userThread" class="thread" aria-live="polite"></div>
    <p id="userError" class="formerror" role="alert"></p>
    <form id="userForm" class="composer">
      <textarea id="userText" rows="1" maxlength="4000" placeholder="Say something" aria-label="Message"></textarea>
      <button id="userSend" class="btn" type="submit">Send</button>
    </form>
  </section>

  <section id="adminView" class="view" hidden>
    <div class="bar">
      <h2>Admin Panel</h2>
      <button id="adminLogout" class="btn ghost" type="button">Log out</button>
    </div>
    <div class="admin">
      <nav id="userList" class="userlist" aria-label="Users"></nav>
      <div class="convo">
        <h3 id="convoTitle">Select a user</h3>
        <div id="adminThread" class="thread" aria-live="polite"></div>
        <p id="adminError" class="formerror" role="alert"></p>
        <form id="adminForm" class="composer" hidden>
          <textarea id="adminText" rows="1" maxlength="4000" placeholder="Write a reply" aria-label="Reply"></textarea>
          <button id="adminSend" class="btn" type="submit">Reply</button>
        </form>
      </div>
    </div>
  </section>
</div>

<script nonce="__NONCE__">
(function () {
  'use strict';

  var POLL_MS = 5000;
  var USERNAME_RE = /^[A-Za-z0-9_]{3,30}$/;
  var $ = function (id) { return document.getElementById(id); };
  var state = { me: null, mode: 'login', users: [], selected: null, lastId: 0, timer: null, tick: 0, inflight: false };

  function api(method, path, body) {
    var opts = { method: method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return fetch(path, opts).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var err = new Error(data.error || 'Something went wrong.');
          err.status = res.status;
          throw err;
        }
        return data;
      });
    });
  }

  function errText(err) {
    return err && err.status ? err.message : 'Network problem. Check your connection and try again.';
  }

  function formatTime(ms) {
    var d = new Date(ms);
    try {
      return d.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    } catch (e) {
      return d.toISOString();
    }
  }

  function clearNode(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function showEmpty(thread, text) {
    var el = document.createElement('div');
    el.className = 'empty';
    el.textContent = text;
    thread.appendChild(el);
  }

  function addMessages(thread, msgs, viewerRole, reset, emptyText) {
    var nearBottom = thread.scrollHeight - thread.scrollTop - thread.clientHeight < 80;
    if (reset) {
      clearNode(thread);
      state.lastId = 0;
    }
    var fresh = msgs.filter(function (m) { return m.id > state.lastId; });
    var empty = thread.querySelector('.empty');
    if (empty && fresh.length) thread.removeChild(empty);
    fresh.forEach(function (m) {
      var el = document.createElement('div');
      el.className = 'msg ' + (m.sender_role === viewerRole ? 'mine' : 'theirs');
      var text = document.createElement('div');
      text.className = 'text';
      text.textContent = m.body;
      var time = document.createElement('div');
      time.className = 'time';
      time.textContent = formatTime(m.created_at);
      el.appendChild(text);
      el.appendChild(time);
      thread.appendChild(el);
      if (m.id > state.lastId) state.lastId = m.id;
    });
    if (!thread.firstChild) showEmpty(thread, emptyText);
    if (reset || nearBottom) thread.scrollTop = thread.scrollHeight;
  }

  function showView(name) {
    ['loadingView', 'authView', 'userView', 'adminView'].forEach(function (id) { $(id).hidden = id !== name; });
    var cls = 'app';
    if (name === 'userView') cls += ' chatting';
    if (name === 'adminView') cls += ' wide';
    $('app').className = cls;
    $('hero').hidden = !(name === 'authView' || name === 'userView');
  }

  function autosize(ta) {
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 140) + 'px';
  }

  /* ----- auth ----- */

  function setMode(mode) {
    state.mode = mode;
    var reg = mode === 'register';
    $('authTitle').textContent = reg ? 'Create account' : 'Log in';
    $('authSubmit').textContent = reg ? 'Create account' : 'Log in';
    $('authSwitch').textContent = reg ? 'I already have an account' : 'Create an account';
    $('authPass').setAttribute('autocomplete', reg ? 'new-password' : 'current-password');
    $('authHint').hidden = !reg;
    $('authError').textContent = '';
  }

  function resetToAuth(message) {
    clearTimeout(state.timer);
    state.me = null;
    state.selected = null;
    state.users = [];
    state.lastId = 0;
    clearNode($('userThread'));
    clearNode($('adminThread'));
    clearNode($('userList'));
    $('userText').value = '';
    $('adminText').value = '';
    $('authPass').value = '';
    $('convoTitle').textContent = 'Select a user';
    $('adminForm').hidden = true;
    $('userError').textContent = '';
    $('adminError').textContent = '';
    setMode('login');
    $('authError').textContent = message || '';
    showView('authView');
  }

  function guard(err) {
    if (err && err.status === 401 && state.me) {
      resetToAuth('Your session ended. Please log in again.');
      return true;
    }
    return false;
  }

  $('authSwitch').addEventListener('click', function () {
    setMode(state.mode === 'login' ? 'register' : 'login');
  });

  $('authForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var username = $('authUser').value.trim();
    var password = $('authPass').value;
    var err = $('authError');
    err.textContent = '';
    if (!username || !password) { err.textContent = 'Enter your username and password.'; return; }
    if (state.mode === 'register') {
      if (!USERNAME_RE.test(username)) { err.textContent = 'Username must be 3-30 characters: letters, numbers and underscore only.'; return; }
      if (password.length < 8) { err.textContent = 'Password must be at least 8 characters.'; return; }
    }
    var btn = $('authSubmit');
    btn.disabled = true;
    api('POST', state.mode === 'register' ? '/api/register' : '/api/login', { username: username, password: password })
      .then(function (data) {
        $('authPass').value = '';
        enter(data.user);
      })
      .catch(function (e2) { err.textContent = errText(e2); })
      .then(function () { btn.disabled = false; });
  });

  function logout() {
    api('POST', '/api/logout').catch(function () {}).then(function () { resetToAuth(''); });
  }
  $('userLogout').addEventListener('click', logout);
  $('adminLogout').addEventListener('click', logout);

  /* ----- entering a session ----- */

  function enter(me) {
    state.me = me;
    state.tick = 0;
    state.lastId = 0;
    if (me.role === 'admin') {
      showView('adminView');
      loadUsers();
    } else {
      $('userName').textContent = me.username;
      showView('userView');
      loadUserMessages(true);
    }
    schedule();
  }

  function schedule() {
    clearTimeout(state.timer);
    state.timer = setTimeout(poll, POLL_MS);
  }

  function poll() {
    if (!state.me) return;
    if (document.hidden) { schedule(); return; }
    state.tick += 1;
    var jobs = [];
    if (state.me.role === 'admin') {
      if (state.tick % 3 === 0) jobs.push(loadUsers());
      if (state.selected) jobs.push(loadConversation(false));
    } else {
      jobs.push(loadUserMessages(false));
    }
    Promise.all(jobs).then(schedule, schedule);
  }

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden && state.me) {
      clearTimeout(state.timer);
      poll();
    }
  });

  /* ----- user view ----- */

  function loadUserMessages(reset) {
    var path = '/api/messages' + (reset ? '' : '?after=' + state.lastId);
    return api('GET', path).then(function (data) {
      if (!state.me || state.me.role !== 'user') return;
      addMessages($('userThread'), data.messages || [], 'user', reset, 'No messages yet. Say something below.');
    }).catch(function (err) { guard(err); });
  }

  $('userText').addEventListener('input', function () { autosize($('userText')); });
  $('userText').addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); $('userSend').click(); }
  });

  $('userForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var ta = $('userText');
    var body = ta.value.trim();
    var err = $('userError');
    err.textContent = '';
    if (!body) return;
    var btn = $('userSend');
    btn.disabled = true;
    api('POST', '/api/messages', { body: body })
      .then(function (data) {
        ta.value = '';
        autosize(ta);
        addMessages($('userThread'), [data.message], 'user', false, '');
        ta.focus();
      })
      .catch(function (e2) { if (!guard(e2)) err.textContent = errText(e2); })
      .then(function () { btn.disabled = false; });
  });

  /* ----- admin view ----- */

  function renderUsers() {
    var list = $('userList');
    clearNode(list);
    if (!state.users.length) {
      var none = document.createElement('div');
      none.className = 'empty';
      none.textContent = 'No users have registered yet.';
      list.appendChild(none);
      return;
    }
    state.users.forEach(function (u) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'uitem';
      if (u.id === state.selected) b.setAttribute('aria-current', 'true');
      var left = document.createElement('span');
      var name = document.createElement('span');
      name.className = 'n';
      name.textContent = u.username;
      var sub = document.createElement('span');
      sub.className = 's';
      sub.textContent = u.message_count ? (u.message_count + ' messages, last ' + formatTime(u.last_message_at)) : 'No messages yet';
      left.appendChild(name);
      left.appendChild(sub);
      b.appendChild(left);
      if (u.last_sender === 'user') {
        var badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = 'Needs reply';
        b.appendChild(badge);
      }
      b.addEventListener('click', function () { selectUser(u); });
      list.appendChild(b);
    });
  }

  function loadUsers() {
    return api('GET', '/api/admin/users').then(function (data) {
      if (!state.me || state.me.role !== 'admin') return;
      state.users = data.users || [];
      renderUsers();
    }).catch(function (err) { guard(err); });
  }

  function selectUser(u) {
    state.selected = u.id;
    $('convoTitle').textContent = u.username;
    $('adminForm').hidden = false;
    $('adminError').textContent = '';
    clearNode($('adminThread'));
    state.lastId = 0;
    renderUsers();
    loadConversation(true);
  }

  function loadConversation(reset) {
    var uid = state.selected;
    if (!uid) return Promise.resolve();
    var path = '/api/admin/messages?user_id=' + uid + (reset ? '' : '&after=' + state.lastId);
    return api('GET', path).then(function (data) {
      if (state.selected !== uid) return; // user switched while loading
      addMessages($('adminThread'), data.messages || [], 'admin', reset, 'No messages from this user yet.');
    }).catch(function (err) { guard(err); });
  }

  $('adminText').addEventListener('input', function () { autosize($('adminText')); });
  $('adminText').addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); $('adminSend').click(); }
  });

  $('adminForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var ta = $('adminText');
    var body = ta.value.trim();
    var err = $('adminError');
    err.textContent = '';
    if (!body || !state.selected) return;
    var uid = state.selected;
    var btn = $('adminSend');
    btn.disabled = true;
    api('POST', '/api/admin/messages', { user_id: uid, body: body })
      .then(function (data) {
        ta.value = '';
        autosize(ta);
        if (state.selected === uid) addMessages($('adminThread'), [data.message], 'admin', false, '');
        ta.focus();
        loadUsers();
      })
      .catch(function (e2) { if (!guard(e2)) err.textContent = errText(e2); })
      .then(function () { btn.disabled = false; });
  });

  /* ----- boot ----- */

  setMode('login');
  api('GET', '/api/me')
    .then(function (data) { enter(data.user); })
    .catch(function (err) {
      resetToAuth(err && !err.status ? errText(err) : '');
    });
})();
</script>
</body>
</html>`;