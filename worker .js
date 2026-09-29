const SESSION_DAYS = 30;
const MAX_MESSAGE = 4000;

// Public user IDs are 8 digits.
const PUBLIC_ID_MIN = 10000000;
const PUBLIC_ID_MAX = 99999999;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders
    }
  });
}

function html(body) {
  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8"
    }
  });
}

function randHex(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);

  return [...a]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function randomPublicId() {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);

  return (
    PUBLIC_ID_MIN +
    (a[0] % (PUBLIC_ID_MAX - PUBLIC_ID_MIN + 1))
  );
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;

  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return diff === 0;
}

function b64(buf) {
  return btoa(
    String.fromCharCode(
      ...new Uint8Array(buf)
    )
  );
}

async function hashPassword(
  password,
  salt = randHex(16)
) {
  const enc = new TextEncoder();

  const key =
    await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: enc.encode(salt),
        iterations: 100000,
        hash: "SHA-256"
      },
      key,
      256
    );

  return `${salt}.${b64(bits)}`;
}

async function verifyPassword(
  password,
  stored
) {
  const parts = stored.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const salt = parts[0];
  const expected = parts[1];

  const actual =
    await hashPassword(
      password,
      salt
    );

  return constantTimeEqual(
    actual,
    `${salt}.${expected}`
  );
}


/*
==================================================
DATABASE
==================================================
*/

async function initDB(db) {

  await db.batch([

    db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at INTEGER NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        role TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `),

    db.prepare(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        sender_role TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )
    `),

    db.prepare(`
      CREATE INDEX IF NOT EXISTS
      idx_messages_user_id_id
      ON messages(user_id, id)
    `),

    db.prepare(`
      CREATE INDEX IF NOT EXISTS
      idx_sessions_expires
      ON sessions(expires_at)
    `),

    /*
      User-to-user conversations.
    */

    db.prepare(`
      CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_a INTEGER NOT NULL,
        user_b INTEGER NOT NULL,

        requested_by INTEGER NOT NULL,

        status TEXT NOT NULL DEFAULT 'pending',

        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,

        UNIQUE(user_a, user_b)
      )
    `),

    db.prepare(`
      CREATE INDEX IF NOT EXISTS
      idx_conversations_user_a
      ON conversations(user_a)
    `),

    db.prepare(`
      CREATE INDEX IF NOT EXISTS
      idx_conversations_user_b
      ON conversations(user_b)
    `),

    db.prepare(`
      CREATE INDEX IF NOT EXISTS
      idx_conversations_status
      ON conversations(status)
    `),

    /*
      Messages belonging to private user-to-user conversations.
    */

    db.prepare(`
      CREATE TABLE IF NOT EXISTS conversation_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        conversation_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,

        body TEXT NOT NULL,

        created_at INTEGER NOT NULL
      )
    `),

    db.prepare(`
      CREATE INDEX IF NOT EXISTS
      idx_conversation_messages_conversation
      ON conversation_messages(conversation_id, id)
    `)

  ]);


  /*
    Add public_id to old installations.

    If the column already exists, SQLite/D1 throws an error.
    That error is intentionally ignored.
  */

  try {

    await db.prepare(`
      ALTER TABLE users
      ADD COLUMN public_id INTEGER
    `).run();

  } catch (_) {
    // Column already exists.
  }


  /*
    Give existing users a public numeric ID.
  */

  const oldUsers =
    await db.prepare(`
      SELECT id
      FROM users
      WHERE public_id IS NULL
    `).all();

  for (
    const user of oldUsers.results || []
  ) {

    let publicId = null;

    for (let attempt = 0; attempt < 20; attempt++) {

      const candidate =
        randomPublicId();

      const exists =
        await db.prepare(`
          SELECT id
          FROM users
          WHERE public_id = ?
        `)
          .bind(candidate)
          .first();

      if (!exists) {
        publicId = candidate;
        break;
      }
    }

    if (publicId === null) {
      throw new Error(
        "Could not generate a unique public user ID."
      );
    }

    await db.prepare(`
      UPDATE users
      SET public_id = ?
      WHERE id = ?
    `)
      .bind(
        publicId,
        user.id
      )
      .run();
  }


  /*
    Unique index for public IDs.
  */

  await db.prepare(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    idx_users_public_id
    ON users(public_id)
  `).run();
}


/*
==================================================
COOKIES / SESSIONS
==================================================
*/

function getCookie(req, name) {

  const cookie =
    req.headers.get("Cookie") || "";

  const match =
    cookie.match(
      new RegExp(
        "(?:^|;\\s*)" +
        name +
        "=([^;]+)"
      )
    );

  return match
    ? match[1]
    : null;
}

function getSessionToken(req) {
  return getCookie(
    req,
    "session"
  );
}

async function getSession(
  req,
  env
) {

  const token =
    getSessionToken(req);

  if (!token) {
    return null;
  }

  const row =
    await env.DB.prepare(`
      SELECT
        token,
        user_id,
        role,
        expires_at
      FROM sessions
      WHERE token = ?
    `)
      .bind(token)
      .first();

  if (!row) {
    return null;
  }

  if (
    row.expires_at <
    Date.now()
  ) {

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `)
      .bind(token)
      .run();

    return null;
  }

  return row;
}

function sessionCookie(token) {

  return [
    `session=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${SESSION_DAYS * 86400}`
  ].join("; ");
}

function deleteSessionCookie() {

  return [
    "session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Max-Age=0"
  ].join("; ");
}

async function requireUser(
  req,
  env
) {

  const session =
    await getSession(
      req,
      env
    );

  if (
    !session ||
    session.role !== "user"
  ) {
    return null;
  }

  return session;
}

async function requireAdmin(
  req,
  env
) {

  const session =
    await getSession(
      req,
      env
    );

  if (
    !session ||
    session.role !== "admin"
  ) {
    return null;
  }

  return session;
}


/*
==================================================
CONVERSATION HELPERS
==================================================
*/

function normalizePair(a, b) {

  a = Number(a);
  b = Number(b);

  if (a < b) {
    return [a, b];
  }

  return [b, a];
}


async function getConversationForUser(
  db,
  conversationId,
  userId
) {

  return await db.prepare(`
    SELECT *
    FROM conversations
    WHERE id = ?
      AND (user_a = ? OR user_b = ?)
  `)
    .bind(
      conversationId,
      userId,
      userId
    )
    .first();
}


async function getUserByPublicIdAndUsername(
  db,
  username,
  publicId
) {

  return await db.prepare(`
    SELECT
      id,
      username,
      public_id,
      role
    FROM users
    WHERE username = ?
      AND public_id = ?
      AND role = 'user'
  `)
    .bind(
      username,
      publicId
    )
    .first();
}


/*
==================================================
HTML
==================================================
*/

const PAGE = `<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>

<title>Private Chat</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: #090b0f;
  color: #f1f3f5;
  font-family:
    system-ui,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
}

.container {
  width: 100%;
  max-width: 950px;
  margin: auto;
  padding: 20px;
}

.card {
  background: #13171c;
  border: 1px solid #252b32;
  border-radius: 18px;
  padding: 20px;
  margin-bottom: 15px;
}

h1 {
  margin: 0;
  font-size: 32px;
}

h2 {
  margin-top: 0;
}

h3 {
  margin-top: 0;
}

.muted {
  color: #9aa3ad;
}

input,
textarea,
button {
  width: 100%;
  padding: 12px;
  border-radius: 12px;
  border: 1px solid #303841;
  background: #0c0f13;
  color: white;
  font: inherit;
}

input {
  margin-bottom: 10px;
}

textarea {
  min-height: 100px;
  resize: vertical;
}

button {
  background: #202730;
  cursor: pointer;
  margin-top: 10px;
}

button:hover {
  background: #2c3540;
}

.row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 15px;
}

.hidden {
  display: none !important;
}

.top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
}

.top button {
  width: auto;
}

.profile-id {
  margin-top: 5px;
  color: #9aa3ad;
}

.profile-id strong {
  color: white;
  font-family: monospace;
  letter-spacing: 1px;
}

.message {
  padding: 12px 15px;
  border-radius: 14px;
  margin: 8px 0;
  white-space: pre-wrap;
  word-break: break-word;
}

.message.mine {
  background: #193522;
}

.message.theirs {
  background: #202735;
}

.message.user {
  background: #193522;
}

.message.admin {
  background: #202735;
}

.timestamp {
  font-size: 12px;
  color: #89929d;
  margin-top: 5px;
}

.status {
  min-height: 22px;
  color: #aab3bd;
}

.user-button {
  text-align: left;
  margin: 5px 0;
}

.request {
  border: 1px solid #303841;
  border-radius: 14px;
  padding: 12px;
  margin: 8px 0;
}

.request-actions {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}

.request-actions button {
  margin-top: 8px;
}

.conversation-button {
  text-align: left;
}

.small {
  font-size: 13px;
}

.empty {
  color: #7f8994;
  padding: 10px 0;
}

@media (max-width: 650px) {

  .row {
    grid-template-columns: 1fr;
  }

  .container {
    padding: 12px;
  }

  h1 {
    font-size: 28px;
  }

}

</style>

</head>

<body>

<div class="container">

<div class="card">

<h1>Private Chat</h1>

<div class="muted">
Talk directly with another user.
</div>

</div>


<!-- AUTH -->

<div
  id="auth"
  class="card"
>

<div class="row">

<div>

<h2>Register</h2>

<input
  id="registerUsername"
  placeholder="Username"
  autocomplete="username"
>

<input
  id="registerPassword"
  type="password"
  placeholder="Password (8+ characters)"
  autocomplete="new-password"
>

<button onclick="registerUser()">
Create account
</button>

</div>


<div>

<h2>Login</h2>

<input
  id="loginUsername"
  placeholder="Username"
  autocomplete="username"
>

<input
  id="loginPassword"
  type="password"
  placeholder="Password"
  autocomplete="current-password"
>

<button onclick="loginUser()">
Login
</button>

</div>

</div>

<p
  id="authStatus"
  class="status"
></p>

</div>


<!-- USER -->

<div
  id="userPanel"
  class="hidden"
>


<div class="card top">

<div>

<div>
Logged in as
<strong id="currentUsername"></strong>
</div>

<div class="profile-id">
Your ID:
<strong id="currentPublicId"></strong>
</div>

</div>

<button
  onclick="logout()"
  style="width:auto"
>
Logout
</button>

</div>


<!-- FIND USER -->

<div class="card">

<h2>Start a conversation</h2>

<p class="muted">
You must enter both the exact username
and the numeric ID of the person.
</p>

<input
  id="targetUsername"
  placeholder="Username"
>

<input
  id="targetPublicId"
  inputmode="numeric"
  placeholder="Numeric User ID"
>

<button onclick="sendConversationRequest()">
Send conversation request
</button>

<p
  id="requestStatus"
  class="status"
></p>

</div>


<!-- REQUESTS -->

<div class="card">

<h3>
Incoming requests
</h3>

<div id="incomingRequests"></div>

</div>


<!-- CONVERSATIONS -->

<div class="card">

<h3>
My conversations
</h3>

<div id="conversationList"></div>

</div>


<!-- CHAT -->

<div
  id="userConversation"
  class="card hidden"
>

<h3 id="conversationTitle">
Conversation
</h3>

<div id="conversationMessages"></div>

<textarea
  id="conversationMessage"
  maxlength="4000"
  placeholder="Write a message..."
></textarea>

<button onclick="sendConversationMessage()">
Send
</button>

</div>


<!-- OLD ADMIN CHAT -->

<div class="card">

<h3>
Administrator
</h3>

<div id="userMessages"></div>

<textarea
  id="userMessage"
  maxlength="4000"
  placeholder="Message the administrator..."
></textarea>

<button onclick="sendUserMessage()">
Send to administrator
</button>

</div>


</div>


<!-- ADMIN -->

<div
  id="adminPanel"
  class="hidden"
>

<div class="card top">

<strong>
Administrator Panel
</strong>

<button
  onclick="logout()"
  style="width:auto"
>
Logout
</button>

</div>


<div class="card">

<h3>
Users
</h3>

<div id="userList"></div>

</div>


<div
  id="adminConversation"
  class="card hidden"
>

<h3 id="selectedUserTitle"></h3>

<div id="adminMessages"></div>

<textarea
  id="adminMessage"
  maxlength="4000"
  placeholder="Reply..."
></textarea>

<button onclick="sendAdminMessage()">
Reply
</button>

</div>

</div>

</div>


<script>

let selectedUserId = null;
let selectedUsername = null;

let selectedConversationId = null;


async function api(
  url,
  options = {}
) {

  const response =
    await fetch(
      url,
      {
        ...options,

        headers: {
          "content-type":
            "application/json",

          ...(options.headers || {})
        }
      }
    );

  let data = {};

  try {
    data =
      await response.json();
  } catch (_) {}

  if (!response.ok) {

    throw new Error(
      data.error ||
      "Request failed"
    );

  }

  return data;
}


function escapeHTML(value) {

  return String(value).replace(
    /[&<>"']/g,
    character => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    })[character]
  );

}


function setAuthStatus(
  message
) {

  document
    .getElementById(
      "authStatus"
    )
    .textContent =
      message;

}


async function registerUser() {

  const username =
    document
      .getElementById(
        "registerUsername"
      )
      .value
      .trim();

  const password =
    document
      .getElementById(
        "registerPassword"
      )
      .value;

  try {

    const result =
      await api(
        "/api/register",
        {
          method: "POST",

          body:
            JSON.stringify({
              username,
              password
            })
        }
      );

    setAuthStatus(
      "Account created. Your numeric ID is " +
      result.public_id +
      ". You can now log in."
    );

  } catch (error) {

    setAuthStatus(
      error.message
    );

  }

}


async function loginUser() {

  const username =
    document
      .getElementById(
        "loginUsername"
      )
      .value
      .trim();

  const password =
    document
      .getElementById(
        "loginPassword"
      )
      .value;

  try {

    await api(
      "/api/login",
      {
        method: "POST",

        body:
          JSON.stringify({
            username,
            password
          })
      }
    );

    await loadCurrentUser();

  } catch (error) {

    setAuthStatus(
      error.message
    );

  }

}


async function loadCurrentUser() {

  const data =
    await api(
      "/api/me"
    );

  document
    .getElementById("auth")
    .classList
    .add("hidden");


  if (
    data.role === "admin"
  ) {

    document
      .getElementById(
        "adminPanel"
      )
      .classList
      .remove("hidden");

    await loadUsers();

    return;
  }


  document
    .getElementById(
      "userPanel"
    )
    .classList
    .remove("hidden");


  document
    .getElementById(
      "currentUsername"
    )
    .textContent =
      data.username;


  document
    .getElementById(
      "currentPublicId"
    )
    .textContent =
      data.public_id;


  await Promise.all([
    loadUserMessages(),
    loadIncomingRequests(),
    loadConversations()
  ]);

}


async function logout() {

  try {

    await api(
      "/api/logout",
      {
        method: "POST"
      }
    );

  } finally {

    location.reload();

  }

}


/*
==================================================
USER -> USER REQUEST
==================================================
*/

async function sendConversationRequest() {

  const username =
    document
      .getElementById(
        "targetUsername"
      )
      .value
      .trim();

  const publicId =
    document
      .getElementById(
        "targetPublicId"
      )
      .value
      .trim();


  const status =
    document
      .getElementById(
        "requestStatus"
      );


  status.textContent =
    "";


  try {

    const result =
      await api(
        "/api/conversations/request",
        {
          method: "POST",

          body:
            JSON.stringify({
              username,
              public_id: publicId
            })
        }
      );


    status.textContent =
      result.message ||
      "Conversation request sent.";

    document
      .getElementById(
        "targetUsername"
      )
      .value = "";

    document
      .getElementById(
        "targetPublicId"
      )
      .value = "";


    await loadConversations();

  } catch (error) {

    status.textContent =
      error.message;

  }

}


/*
==================================================
INCOMING REQUESTS
==================================================
*/

async function loadIncomingRequests() {

  const data =
    await api(
      "/api/conversations/requests"
    );


  const container =
    document
      .getElementById(
        "incomingRequests"
      );


  if (
    !data.requests.length
  ) {

    container.innerHTML =
      '<div class="empty">No pending requests.</div>';

    return;
  }


  container.innerHTML =
    data.requests
      .map(request => {

        return \`
          <div class="request">

            <strong>
              \${escapeHTML(request.username)}
            </strong>

            <div class="muted small">
              ID:
              \${escapeHTML(request.public_id)}
            </div>

            <div class="request-actions">

              <button
                onclick="respondToRequest(\${request.id}, 'accepted')"
              >
                Accept
              </button>

              <button
                onclick="respondToRequest(\${request.id}, 'rejected')"
              >
                Reject
              </button>

            </div>

          </div>
        \`;

      })
      .join("");

}


async function respondToRequest(
  conversationId,
  status
) {

  try {

    await api(
      "/api/conversations/respond",
      {
        method: "POST",

        body:
          JSON.stringify({
            conversation_id:
              conversationId,

            status
          })
      }
    );


    await loadIncomingRequests();
    await loadConversations();

  } catch (error) {

    alert(
      error.message
    );

  }

}


/*
==================================================
CONVERSATIONS
==================================================
*/

async function loadConversations() {

  const data =
    await api(
      "/api/conversations"
    );


  const container =
    document
      .getElementById(
        "conversationList"
      );


  if (
    !data.conversations.length
  ) {

    container.innerHTML =
      '<div class="empty">No active conversations.</div>';

    return;
  }


  container.innerHTML =
    data.conversations
      .map(conversation => {

        return \`
          <button
            class="conversation-button"
            onclick="openConversation(\${conversation.id})"
          >

            <strong>
              \${escapeHTML(conversation.username)}
            </strong>

            <span class="muted">
              —
              ID:
              \${escapeHTML(conversation.public_id)}
            </span>

          </button>
        \`;

      })
      .join("");

}


async function openConversation(
  conversationId
) {

  selectedConversationId =
    conversationId;


  const data =
    await api(
      "/api/conversations/" +
      encodeURIComponent(
        conversationId
      )
    );


  document
    .getElementById(
      "userConversation"
    )
    .classList
    .remove("hidden");


  document
    .getElementById(
      "conversationTitle"
    )
    .textContent =
      "Conversation with " +
      data.user.username +
      " (" +
      data.user.public_id +
      ")";


  renderConversationMessages(
    data.messages
  );

}


function renderConversationMessages(
  messages
) {

  const container =
    document
      .getElementById(
        "conversationMessages"
      );


  container.innerHTML =
    messages
      .map(message => {

        const mine =
          message.mine;


        return \`
          <div
            class="message \${mine ? "mine" : "theirs"}"
          >

            <div>
              \${escapeHTML(message.body)}
            </div>

            <div class="timestamp">
              \${new Date(
                message.created_at
              ).toLocaleString()}
            </div>

          </div>
        \`;

      })
      .join("");


  container.scrollTop =
    container.scrollHeight;

}


async function sendConversationMessage() {

  if (
    !selectedConversationId
  ) {
    return;
  }


  const input =
    document
      .getElementById(
        "conversationMessage"
      );


  const body =
    input.value.trim();


  if (!body) {
    return;
  }


  try {

    await api(
      "/api/conversations/message",
      {
        method: "POST",

        body:
          JSON.stringify({
            conversation_id:
              selectedConversationId,

            body
          })
      }
    );


    input.value = "";

    await openConversation(
      selectedConversationId
    );

  } catch (error) {

    alert(
      error.message
    );

  }

}


/*
==================================================
OLD ADMIN CHAT
==================================================
*/

async function loadUserMessages() {

  const data =
    await api(
      "/api/messages"
    );


  const container =
    document
      .getElementById(
        "userMessages"
      );


  container.innerHTML =
    data.messages
      .map(message => {

        return \`
          <div
            class="message \${message.sender_role}"
          >

            <div>
              \${escapeHTML(message.body)}
            </div>

            <div class="timestamp">
              \${new Date(
                message.created_at
              ).toLocaleString()}
            </div>

          </div>
        \`;

      })
      .join("");

}


async function sendUserMessage() {

  const input =
    document
      .getElementById(
        "userMessage"
      );


  const body =
    input.value.trim();


  if (!body) {
    return;
  }


  try {

    await api(
      "/api/messages",
      {
        method: "POST",

        body:
          JSON.stringify({
            body
          })
      }
    );


    input.value = "";

    await loadUserMessages();

  } catch (error) {

    alert(
      error.message
    );

  }

}


/*
==================================================
ADMIN
==================================================
*/

async function loadUsers() {

  const data =
    await api(
      "/api/admin/users"
    );


  const container =
    document
      .getElementById(
        "userList"
      );


  if (
    !data.users.length
  ) {

    container.innerHTML =
      '<div class="muted">No users yet.</div>';

    return;
  }


  container.innerHTML =
    data.users
      .map(user => {

        return \`
          <button
            class="user-button"
            onclick="selectUser(\${user.id})"
          >

            <strong>
              \${escapeHTML(user.username)}
            </strong>

            <div class="muted small">
              ID:
              \${escapeHTML(user.public_id)}
            </div>

          </button>
        \`;

      })
      .join("");

}


async function selectUser(
  userId
) {

  const data =
    await api(
      "/api/admin/users"
    );


  const user =
    data.users.find(
      item =>
        item.id === userId
    );


  if (!user) {
    return;
  }


  selectedUserId =
    user.id;

  selectedUsername =
    user.username;


  document
    .getElementById(
      "adminConversation"
    )
    .classList
    .remove("hidden");


  document
    .getElementById(
      "selectedUserTitle"
    )
    .textContent =
      "Conversation with " +
      user.username +
      " (" +
      user.public_id +
      ")";


  await loadAdminMessages();

}


async function loadAdminMessages() {

  if (!selectedUserId) {
    return;
  }


  const data =
    await api(
      "/api/admin/messages?user_id=" +
      encodeURIComponent(
        selectedUserId
      )
    );


  const container =
    document
      .getElementById(
        "adminMessages"
      );


  container.innerHTML =
    data.messages
      .map(message => {

        return \`
          <div
            class="message \${message.sender_role}"
          >

            <div>
              \${escapeHTML(message.body)}
            </div>

            <div class="timestamp">
              \${new Date(
                message.created_at
              ).toLocaleString()}
            </div>

          </div>
        \`;

      })
      .join("");

}


async function sendAdminMessage() {

  if (!selectedUserId) {
    return;
  }


  const input =
    document
      .getElementById(
        "adminMessage"
      );


  const body =
    input.value.trim();


  if (!body) {
    return;
  }


  try {

    await api(
      "/api/admin/messages",
      {
        method: "POST",

        body:
          JSON.stringify({
            user_id:
              selectedUserId,

            body
          })
      }
    );


    input.value = "";

    await loadAdminMessages();

  } catch (error) {

    alert(
      error.message
    );

  }

}


/*
==================================================
INITIALIZE
==================================================
*/

async function initialize() {

  try {

    await loadCurrentUser();

  } catch (_) {

    // Not logged in.

  }

}

initialize();


/*
==================================================
AUTO REFRESH
==================================================
*/

setInterval(
  async () => {

    try {

      const auth =
        document
          .getElementById(
            "auth"
          );


      if (
        !auth.classList.contains(
          "hidden"
        )
      ) {
        return;
      }


      const adminPanel =
        document
          .getElementById(
            "adminPanel"
          );


      if (
        adminPanel.classList.contains(
          "hidden"
        )
      ) {

        await loadIncomingRequests();

        await loadConversations();

        await loadUserMessages();


        if (
          selectedConversationId
        ) {

          await openConversation(
            selectedConversationId
          );

        }

      } else {

        await loadUsers();


        if (
          selectedUserId
        ) {

          await loadAdminMessages();

        }

      }

    } catch (_) {}

  },
  5000
);

</script>

</body>

</html>`;


/*
==================================================
WORKER
==================================================
*/

export default {

  async fetch(
    request,
    env
  ) {

    try {

      if (!env.DB) {

        return json(
          {
            error:
              "D1 binding DB is missing."
          },
          500
        );

      }


      await initDB(
        env.DB
      );


      const url =
        new URL(
          request.url
        );

      const path =
        url.pathname;


      /*
      ==============================================
      FRONTEND
      ==============================================
      */

      if (
        request.method === "GET" &&
        path === "/"
      ) {

        return html(
          PAGE
        );

      }


      /*
      ==============================================
      REGISTER
      ==============================================
      */

      if (
        request.method === "POST" &&
        path === "/api/register"
      ) {

        const {
          username,
          password
        } =
          await request.json();


        if (
          !/^[A-Za-z0-9_]{3,30}$/.test(
            username || ""
          )
        ) {

          return json(
            {
              error:
                "Username must contain 3-30 letters, numbers, or underscore."
            },
            400
          );

        }


        if (
          !password ||
          password.length < 8
        ) {

          return json(
            {
              error:
                "Password must be at least 8 characters."
            },
            400
          );

        }


        const existing =
          await env.DB.prepare(`
            SELECT id
            FROM users
            WHERE username = ?
          `)
            .bind(
              username
            )
            .first();


        if (existing) {

          return json(
            {
              error:
                "Username already exists."
            },
            409
          );

        }


        let publicId = null;


        for (
          let attempt = 0;
          attempt < 30;
          attempt++
        ) {

          const candidate =
            randomPublicId();


          const exists =
            await env.DB.prepare(`
              SELECT id
              FROM users
              WHERE public_id = ?
            `)
              .bind(candidate)
              .first();


          if (!exists) {

            publicId =
              candidate;

            break;

          }

        }


        if (
          publicId === null
        ) {

          return json(
            {
              error:
                "Could not generate a unique user ID."
            },
            500
          );

        }


        const passwordHash =
          await hashPassword(
            password
          );


        await env.DB.prepare(`
          INSERT INTO users
          (
            username,
            password_hash,
            role,
            created_at,
            public_id
          )
          VALUES (?, ?, ?, ?, ?)
        `)
          .bind(
            username,
            passwordHash,
            "user",
            Date.now(),
            publicId
          )
          .run();


        return json(
          {
            ok: true,
            username,
            public_id:
              publicId
          }
        );

      }


      /*
      ==============================================
      LOGIN
      ==============================================
      */

      if (
        request.method === "POST" &&
        path === "/api/login"
      ) {

        const {
          username,
          password
        } =
          await request.json();


        /*
        ADMIN
        */

        if (
          username === "admin"
        ) {

          if (
            typeof env.ADMIN_PASSWORD !==
            "string" ||
            !env.ADMIN_PASSWORD
          ) {

            return json(
              {
                error:
                  "ADMIN_PASSWORD secret is not configured on this Worker."
              },
              500
            );

          }


          if (
            password !==
            env.ADMIN_PASSWORD
          ) {

            return json(
              {
                error:
                  "Invalid admin password."
              },
              401
            );

          }


          const token =
            randHex(32);


          await env.DB.prepare(`
            INSERT OR REPLACE INTO sessions
            (
              token,
              user_id,
              role,
              expires_at
            )
            VALUES (?, ?, ?, ?)
          `)
            .bind(
              token,
              0,
              "admin",
              Date.now() +
              SESSION_DAYS *
              86400000
            )
            .run();


          return json(
            {
              ok: true,
              role: "admin",
              username: "admin"
            },
            200,
            {
              "set-cookie":
                sessionCookie(
                  token
                )
            }
          );

        }


        /*
        NORMAL USER
        */

        const user =
          await env.DB.prepare(`
            SELECT
              id,
              username,
              public_id,
              password_hash,
              role
            FROM users
            WHERE username = ?
          `)
            .bind(
              username || ""
            )
            .first();


        if (!user) {

          return json(
            {
              error:
                "Invalid username or password."
            },
            401
          );

        }


        const valid =
          await verifyPassword(
            password || "",
            user.password_hash
          );


        if (!valid) {

          return json(
            {
              error:
                "Invalid username or password."
            },
            401
          );

        }


        const token =
          randHex(32);


        await env.DB.prepare(`
          INSERT INTO sessions
          (
            token,
            user_id,
            role,
            expires_at
          )
          VALUES (?, ?, ?, ?)
        `)
          .bind(
            token,
            user.id,
            "user",
            Date.now() +
            SESSION_DAYS *
            86400000
          )
          .run();


        return json(
          {
            ok: true,
            role: "user",
            username:
              user.username,
            public_id:
              user.public_id
          },
          200,
          {
            "set-cookie":
              sessionCookie(
                token
              )
          }
        );

      }


      /*
      ==============================================
      LOGOUT
      ==============================================
      */

      if (
        request.method === "POST" &&
        path === "/api/logout"
      ) {

        const token =
          getSessionToken(
            request
          );


        if (token) {

          await env.DB.prepare(`
            DELETE FROM sessions
            WHERE token = ?
          `)
            .bind(token)
            .run();

        }


        return json(
          {
            ok: true
          },
          200,
          {
            "set-cookie":
              deleteSessionCookie()
          }
        );

      }


      /*
      ==============================================
      CURRENT USER
      ==============================================
      */

      if (
        request.method === "GET" &&
        path === "/api/me"
      ) {

        const session =
          await getSession(
            request,
            env
          );


        if (!session) {

          return json(
            {
              authenticated:
                false
            },
            401
          );

        }


        if (
          session.role === "admin"
        ) {

          return json({
            authenticated:
              true,

            role:
              "admin",

            username:
              "admin"
          });

        }


        const user =
          await env.DB.prepare(`
            SELECT
              username,
              public_id
            FROM users
            WHERE id = ?
          `)
            .bind(
              session.user_id
            )
            .first();


        return json({
          authenticated:
            true,

          role:
            "user",

          username:
            user?.username ||
            "user",

          public_id:
            user?.public_id ||
            null
        });

      }


      /*
      ==================================================
      SEND USER -> ADMIN MESSAGE
      ==================================================
      */

      if (
        request.method === "GET" &&
        path === "/api/messages"
      ) {

        const session =
          await requireUser(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const rows =
          await env.DB.prepare(`
            SELECT
              id,
              sender_role,
              body,
              created_at
            FROM messages
            WHERE user_id = ?
            ORDER BY id ASC
          `)
            .bind(
              session.user_id
            )
            .all();


        return json({
          messages:
            rows.results ||
            []
        });

      }


      if (
        request.method === "POST" &&
        path === "/api/messages"
      ) {

        const session =
          await requireUser(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const {
          body
        } =
          await request.json();


        if (
          typeof body !==
            "string" ||
          !body.trim() ||
          body.length >
            MAX_MESSAGE
        ) {

          return json(
            {
              error:
                "Invalid message."
            },
            400
          );

        }


        await env.DB.prepare(`
          INSERT INTO messages
          (
            user_id,
            sender_role,
            body,
            created_at
          )
          VALUES (?, ?, ?, ?)
        `)
          .bind(
            session.user_id,
            "user",
            body.trim(),
            Date.now()
          )
          .run();


        return json({
          ok: true
        });

      }


      /*
      ==================================================
      USER-TO-USER
      SEND REQUEST
      ==================================================
      */

      if (
        request.method === "POST" &&
        path === "/api/conversations/request"
      ) {

        const session =
          await requireUser(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const {
          username,
          public_id
        } =
          await request.json();


        const targetUsername =
          String(
            username || ""
          ).trim();


        const targetPublicId =
          Number(
            public_id
          );


        if (
          !targetUsername ||
          !Number.isInteger(
            targetPublicId
          )
        ) {

          return json(
            {
              error:
                "Both username and numeric user ID are required."
            },
            400
          );

        }


        const target =
          await getUserByPublicIdAndUsername(
            env.DB,
            targetUsername,
            targetPublicId
          );


        if (!target) {

          return json(
            {
              error:
                "Username and ID do not match any user."
            },
            404
          );

        }


        if (
          target.id ===
          session.user_id
        ) {

          return json(
            {
              error:
                "You cannot start a conversation with yourself."
            },
            400
          );

        }


        const [
          userA,
          userB
        ] =
          normalizePair(
            session.user_id,
            target.id
          );


        const existing =
          await env.DB.prepare(`
            SELECT *
            FROM conversations
            WHERE user_a = ?
              AND user_b = ?
          `)
            .bind(
              userA,
              userB
            )
            .first();


        if (existing) {

          if (
            existing.status ===
            "accepted"
          ) {

            return json(
              {
                error:
                  "A conversation with this user already exists."
              },
              409
            );

          }


          if (
            existing.status ===
            "pending"
          ) {

            return json(
              {
                error:
                  "A conversation request is already pending."
              },
              409
            );

          }


          /*
            Allow a rejected conversation
            to be requested again.
          */

          await env.DB.prepare(`
            UPDATE conversations
            SET
              requested_by = ?,
              status = 'pending',
              updated_at = ?
            WHERE id = ?
          `)
            .bind(
              session.user_id,
              Date.now(),
              existing.id
            )
            .run();


          return json({
            ok: true,
            message:
              "Conversation request sent again."
          });

        }


        await env.DB.prepare(`
          INSERT INTO conversations
          (
            user_a,
            user_b,
            requested_by,
            status,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, 'pending', ?, ?)
        `)
          .bind(
            userA,
            userB,
            session.user_id,
            Date.now(),
            Date.now()
          )
          .run();


        return json({
          ok: true,
          message:
            "Conversation request sent."
        });

      }


      /*
      ==================================================
      INCOMING REQUESTS
      ==================================================
      */

      if (
        request.method === "GET" &&
        path === "/api/conversations/requests"
      ) {

        const session =
          await requireUser(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const rows =
          await env.DB.prepare(`
            SELECT
              c.id,
              c.created_at,
              u.username,
              u.public_id
            FROM conversations c
            JOIN users u
              ON u.id = c.requested_by
            WHERE
              c.status = 'pending'
              AND c.requested_by != ?
              AND
              (
                c.user_a = ?
                OR
                c.user_b = ?
              )
            ORDER BY c.created_at DESC
          `)
            .bind(
              session.user_id,
              session.user_id,
              session.user_id
            )
            .all();


        return json({
          requests:
            rows.results ||
            []
        });

      }


      /*
      ==================================================
      ACCEPT / REJECT REQUEST
      ==================================================
      */

      if (
        request.method === "POST" &&
        path === "/api/conversations/respond"
      ) {

        const session =
          await requireUser(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const {
          conversation_id,
          status
        } =
          await request.json();


        const conversationId =
          Number(
            conversation_id
          );


        if (
          !Number.isInteger(
            conversationId
          )
        ) {

          return json(
            {
              error:
                "Invalid conversation ID."
            },
            400
          );

        }


        if (
          status !== "accepted" &&
          status !== "rejected"
        ) {

          return json(
            {
              error:
                "Invalid response."
            },
            400
          );

        }


        const conversation =
          await getConversationForUser(
            env.DB,
            conversationId,
            session.user_id
          );


        if (!conversation) {

          return json(
            {
              error:
                "Conversation not found."
            },
            404
          );

        }


        if (
          conversation.status !==
          "pending"
        ) {

          return json(
            {
              error:
                "This request has already been handled."
            },
            409
          );

        }


        /*
          Only the recipient may accept/reject.
        */

        if (
          conversation.requested_by ===
          session.user_id
        ) {

          return json(
            {
              error:
                "You cannot accept your own request."
            },
            403
          );

        }


        await env.DB.prepare(`
          UPDATE conversations
          SET
            status = ?,
            updated_at = ?
          WHERE id = ?
        `)
          .bind(
            status,
            Date.now(),
            conversationId
          )
          .run();


        return json({
          ok: true,
          status
        });

      }


      /*
      ==================================================
      LIST ACCEPTED CONVERSATIONS
      ==================================================
      */

      if (
        request.method === "GET" &&
        path === "/api/conversations"
      ) {

        const session =
          await requireUser(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const rows =
          await env.DB.prepare(`
            SELECT
              c.id,
              c.status,
              c.updated_at,

              u.username,
              u.public_id

            FROM conversations c

            JOIN users u
              ON u.id =
                CASE
                  WHEN c.user_a = ?
                  THEN c.user_b
                  ELSE c.user_a
                END

            WHERE
              c.status = 'accepted'
              AND
              (
                c.user_a = ?
                OR
                c.user_b = ?
              )

            ORDER BY
              c.updated_at DESC
          `)
            .bind(
              session.user_id,
              session.user_id,
              session.user_id
            )
            .all();


        return json({
          conversations:
            rows.results ||
            []
        });

      }


      /*
      ==================================================
      OPEN CONVERSATION
      ==================================================
      */

      const conversationMatch =
        path.match(
          /^\\/api\\/conversations\\/(\\d+)$/
        );


      if (
        request.method === "GET" &&
        conversationMatch
      ) {

        const session =
          await requireUser(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const conversationId =
          Number(
            conversationMatch[1]
          );


        const conversation =
          await getConversationForUser(
            env.DB,
            conversationId,
            session.user_id
          );


        if (!conversation) {

          return json(
            {
              error:
                "Conversation not found."
            },
            404
          );

        }


        if (
          conversation.status !==
          "accepted"
        ) {

          return json(
            {
              error:
                "Conversation is not active."
            },
            403
          );

        }


        const otherUserId =
          conversation.user_a ===
          session.user_id
            ? conversation.user_b
            : conversation.user_a;


        const otherUser =
          await env.DB.prepare(`
            SELECT
              username,
              public_id
            FROM users
            WHERE id = ?
          `)
            .bind(
              otherUserId
            )
            .first();


        const messages =
          await env.DB.prepare(`
            SELECT
              id,
              sender_id,
              body,
              created_at
            FROM conversation_messages
            WHERE conversation_id = ?
            ORDER BY id ASC
          `)
            .bind(
              conversationId
            )
            .all();


        return json({
          conversation: {
            id:
              conversation.id,

            status:
              conversation.status
          },

          user: {
            username:
              otherUser?.username,

            public_id:
              otherUser?.public_id
          },

          messages:
            (
              messages.results ||
              []
            ).map(
              message => ({
                id:
                  message.id,

                body:
                  message.body,

                created_at:
                  message.created_at,

                mine:
                  message.sender_id ===
                  session.user_id
              })
            )
        });

      }


      /*
      ==================================================
      SEND PRIVATE MESSAGE
      ==================================================
      */

      if (
        request.method === "POST" &&
        path === "/api/conversations/message"
      ) {

        const session =
          await requireUser(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const {
          conversation_id,
          body
        } =
          await request.json();


        const conversationId =
          Number(
            conversation_id
          );


        if (
          !Number.isInteger(
            conversationId
          )
        ) {

          return json(
            {
              error:
                "Invalid conversation ID."
            },
            400
          );

        }


        if (
          typeof body !==
            "string" ||
          !body.trim() ||
          body.length >
            MAX_MESSAGE
        ) {

          return json(
            {
              error:
                "Invalid message."
            },
            400
          );

        }


        const conversation =
          await getConversationForUser(
            env.DB,
            conversationId,
            session.user_id
          );


        if (!conversation) {

          return json(
            {
              error:
                "Conversation not found."
            },
            404
          );

        }


        if (
          conversation.status !==
          "accepted"
        ) {

          return json(
            {
              error:
                "Conversation is not active."
            },
            403
          );

        }


        const now =
          Date.now();


        await env.DB.batch([

          env.DB.prepare(`
            INSERT INTO conversation_messages
            (
              conversation_id,
              sender_id,
              body,
              created_at
            )
            VALUES (?, ?, ?, ?)
          `)
            .bind(
              conversationId,
              session.user_id,
              body.trim(),
              now
            ),

          env.DB.prepare(`
            UPDATE conversations
            SET updated_at = ?
            WHERE id = ?
          `)
            .bind(
              now,
              conversationId
            )

        ]);


        return json({
          ok: true
        });

      }


      /*
      ==================================================
      ADMIN USERS
      ==================================================
      */

      if (
        request.method === "GET" &&
        path === "/api/admin/users"
      ) {

        const session =
          await requireAdmin(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const rows =
          await env.DB.prepare(`
            SELECT
              id,
              username,
              public_id,
              created_at
            FROM users
            WHERE role = 'user'
            ORDER BY username ASC
          `)
            .all();


        return json({
          users:
            rows.results ||
            []
        });

      }


      /*
      ==================================================
      ADMIN READ MESSAGES
      ==================================================
      */

      if (
        request.method === "GET" &&
        path === "/api/admin/messages"
      ) {

        const session =
          await requireAdmin(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const userId =
          Number(
            url.searchParams.get(
              "user_id"
            )
          );


        if (
          !Number.isInteger(
            userId
          ) ||
          userId <= 0
        ) {

          return json(
            {
              error:
                "Valid user_id is required."
            },
            400
          );

        }


        const rows =
          await env.DB.prepare(`
            SELECT
              id,
              sender_role,
              body,
              created_at
            FROM messages
            WHERE user_id = ?
            ORDER BY id ASC
          `)
            .bind(
              userId
            )
            .all();


        return json({
          messages:
            rows.results ||
            []
        });

      }


      /*
      ==================================================
      ADMIN SEND MESSAGE
      ==================================================
      */

      if (
        request.method === "POST" &&
        path === "/api/admin/messages"
      ) {

        const session =
          await requireAdmin(
            request,
            env
          );


        if (!session) {

          return json(
            {
              error:
                "Unauthorized"
            },
            401
          );

        }


        const {
          user_id,
          body
        } =
          await request.json();


        const userId =
          Number(
            user_id
          );


        if (
          !Number.isInteger(
            userId
          ) ||
          userId <= 0
        ) {

          return json(
            {
              error:
                "Invalid user_id."
            },
            400
          );

        }


        if (
          typeof body !==
            "string" ||
          !body.trim() ||
          body.length >
            MAX_MESSAGE
        ) {

          return json(
            {
              error:
                "Invalid message."
            },
            400
          );

        }


        const user =
          await env.DB.prepare(`
            SELECT id
            FROM users
            WHERE id = ?
              AND role = 'user'
          `)
            .bind(
              userId
            )
            .first();


        if (!user) {

          return json(
            {
              error:
                "User not found."
            },
            404
          );

        }


        await env.DB.prepare(`
          INSERT INTO messages
          (
            user_id,
            sender_role,
            body,
            created_at
          )
          VALUES (?, ?, ?, ?)
        `)
          .bind(
            userId,
            "admin",
            body.trim(),
            Date.now()
          )
          .run();


        return json({
          ok: true
        });

      }


      /*
      ==============================================
      NOT FOUND
      ==============================================
      */

      return new Response(
        "Not Found",
        {
          status: 404
        }
      );


    } catch (error) {

      console.error(
        error
      );


      return json(
        {
          error:
            error?.message ||
            "Internal server error."
        },
        500
      );

    }

  }

};