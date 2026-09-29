const SESSION_DAYS = 30;
const MAX_MESSAGE = 4000;

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
    headers: { "content-type": "text/html; charset=utf-8" }
  });
}

function randHex(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;

  let diff = 0;

  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return diff === 0;
}

function b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function hashPassword(password, salt = randHex(16)) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
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

async function verifyPassword(password, stored) {
  const parts = stored.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const salt = parts[0];
  const expected = parts[1];

  const actual = await hashPassword(password, salt);

  return constantTimeEqual(
    actual,
    `${salt}.${expected}`
  );
}

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
    `)
  ]);
}

function getCookie(req, name) {
  const cookie = req.headers.get("Cookie") || "";

  const match = cookie.match(
    new RegExp("(?:^|;\\s*)" + name + "=([^;]+)")
  );

  return match ? match[1] : null;
}

function getSessionToken(req) {
  return getCookie(req, "session");
}

async function getSession(req, env) {
  const token = getSessionToken(req);

  if (!token) {
    return null;
  }

  const row = await env.DB.prepare(`
    SELECT token, user_id, role, expires_at
    FROM sessions
    WHERE token = ?
  `)
    .bind(token)
    .first();

  if (!row) {
    return null;
  }

  if (row.expires_at < Date.now()) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE token = ?"
    )
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

async function requireUser(req, env) {
  const session = await getSession(req, env);

  if (!session || session.role !== "user") {
    return null;
  }

  return session;
}

async function requireAdmin(req, env) {
  const session = await getSession(req, env);

  if (!session || session.role !== "admin") {
    return null;
  }

  return session;
}

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
  min-height: 110px;
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

.message {
  padding: 12px 15px;
  border-radius: 14px;
  margin: 8px 0;
  white-space: pre-wrap;
  word-break: break-word;
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

.user-button {
  text-align: left;
  margin: 5px 0;
}

.status {
  min-height: 22px;
  color: #aab3bd;
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

    <h1>Hello</h1>

    <div class="muted">
      I'm there
    </div>

    <p>
      Say something
    </p>

  </div>


  <!-- AUTH -->

  <div id="auth" class="card">

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

    <p id="authStatus" class="status"></p>

  </div>


  <!-- USER -->

  <div id="userPanel" class="hidden">

    <div class="card top">

      <div>
        Logged in as
        <strong id="currentUsername"></strong>
      </div>

      <button onclick="logout()" style="width:auto">
        Logout
      </button>

    </div>


    <div class="card">

      <div id="userMessages"></div>

      <textarea
        id="userMessage"
        maxlength="4000"
        placeholder="Say something..."
      ></textarea>

      <button onclick="sendUserMessage()">
        Send
      </button>

    </div>

  </div>


  <!-- ADMIN -->

  <div id="adminPanel" class="hidden">

    <div class="card top">

      <strong>
        Administrator Panel
      </strong>

      <button onclick="logout()" style="width:auto">
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


async function api(url, options = {}) {

  const response = await fetch(url, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });

  let data = {};

  try {
    data = await response.json();
  } catch (_) {}

  if (!response.ok) {
    throw new Error(
      data.error || "Request failed"
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


function setAuthStatus(message) {

  document.getElementById(
    "authStatus"
  ).textContent = message;

}


async function registerUser() {

  const username =
    document.getElementById(
      "registerUsername"
    ).value.trim();

  const password =
    document.getElementById(
      "registerPassword"
    ).value;

  try {

    await api(
      "/api/register",
      {
        method: "POST",
        body: JSON.stringify({
          username,
          password
        })
      }
    );

    setAuthStatus(
      "Account created. You can now log in."
    );

  } catch (error) {

    setAuthStatus(
      error.message
    );

  }

}


async function loginUser() {

  const username =
    document.getElementById(
      "loginUsername"
    ).value.trim();

  const password =
    document.getElementById(
      "loginPassword"
    ).value;

  try {

    const result = await api(
      "/api/login",
      {
        method: "POST",
        body: JSON.stringify({
          username,
          password
        })
      }
    );

    if (result.role === "admin") {

      await loadCurrentUser();

      return;

    }

    await loadCurrentUser();

  } catch (error) {

    setAuthStatus(
      error.message
    );

  }

}


async function loadCurrentUser() {

  const data =
    await api("/api/me");

  document
    .getElementById("auth")
    .classList
    .add("hidden");


  if (data.role === "admin") {

    document
      .getElementById("adminPanel")
      .classList
      .remove("hidden");

    await loadUsers();

    return;

  }


  document
    .getElementById("userPanel")
    .classList
    .remove("hidden");

  document
    .getElementById("currentUsername")
    .textContent = data.username;

  await loadUserMessages();

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


async function loadUserMessages() {

  const data =
    await api("/api/messages");

  const container =
    document.getElementById(
      "userMessages"
    );

  container.innerHTML =
    data.messages.map(message => {

      return \`
        <div class="message \${message.sender_role}">
          <div>\${escapeHTML(message.body)}</div>
          <div class="timestamp">
            \${new Date(message.created_at).toLocaleString()}
          </div>
        </div>
      \`;

    }).join("");

}


async function sendUserMessage() {

  const input =
    document.getElementById(
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
        body: JSON.stringify({
          body
        })
      }
    );

    input.value = "";

    await loadUserMessages();

  } catch (error) {

    alert(error.message);

  }

}


async function loadUsers() {

  const data =
    await api(
      "/api/admin/users"
    );

  const container =
    document.getElementById(
      "userList"
    );

  if (!data.users.length) {

    container.innerHTML =
      '<div class="muted">No users yet.</div>';

    return;

  }

  container.innerHTML =
    data.users.map(user => {

      const safeName =
        escapeHTML(user.username);

      return \`
        <button
          class="user-button"
          onclick="selectUser(\${user.id})"
        >
          \${safeName}
        </button>
      \`;

    }).join("");

}


async function selectUser(userId) {

  const data =
    await api(
      "/api/admin/users"
    );

  const user =
    data.users.find(
      item => item.id === userId
    );

  if (!user) {
    return;
  }

  selectedUserId = user.id;
  selectedUsername = user.username;

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
      user.username;

  await loadAdminMessages();

}


async function loadAdminMessages() {

  if (!selectedUserId) {
    return;
  }

  const data =
    await api(
      "/api/admin/messages?user_id=" +
      encodeURIComponent(selectedUserId)
    );

  const container =
    document.getElementById(
      "adminMessages"
    );

  container.innerHTML =
    data.messages.map(message => {

      return \`
        <div class="message \${message.sender_role}">
          <div>\${escapeHTML(message.body)}</div>
          <div class="timestamp">
            \${new Date(message.created_at).toLocaleString()}
          </div>
        </div>
      \`;

    }).join("");

}


async function sendAdminMessage() {

  if (!selectedUserId) {
    return;
  }

  const input =
    document.getElementById(
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
        body: JSON.stringify({
          user_id: selectedUserId,
          body
        })
      }
    );

    input.value = "";

    await loadAdminMessages();

  } catch (error) {

    alert(error.message);

  }

}


async function initialize() {

  try {

    await loadCurrentUser();

  } catch (_) {

    // User is not logged in.

  }

}


initialize();


setInterval(
  async () => {

    try {

      const auth =
        document.getElementById(
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
        document.getElementById(
          "adminPanel"
        );

      if (
        adminPanel.classList.contains(
          "hidden"
        )
      ) {

        await loadUserMessages();

      } else {

        await loadUsers();

        if (selectedUserId) {
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


export default {

  async fetch(request, env) {

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


      await initDB(env.DB);


      const url =
        new URL(request.url);

      const path =
        url.pathname;


      // =========================
      // FRONTEND
      // =========================

      if (
        request.method === "GET" &&
        path === "/"
      ) {

        return html(PAGE);

      }


      // =========================
      // REGISTER
      // =========================

      if (
        request.method === "POST" &&
        path === "/api/register"
      ) {

        const {
          username,
          password
        } = await request.json();


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
            .bind(username)
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
            created_at
          )
          VALUES (?, ?, ?, ?)
        `)
          .bind(
            username,
            passwordHash,
            "user",
            Date.now()
          )
          .run();


        return json({
          ok: true
        });

      }


      // =========================
      // LOGIN
      // =========================

      if (
        request.method === "POST" &&
        path === "/api/login"
      ) {

        const {
          username,
          password
        } = await request.json();


        // -------------------------
        // ADMIN LOGIN
        // -------------------------

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
                sessionCookie(token)
            }
          );

        }


        // -------------------------
        // NORMAL USER LOGIN
        // -------------------------

        const user =
          await env.DB.prepare(`
            SELECT
              id,
              username,
              password_hash,
              role
            FROM users
            WHERE username = ?
          `)
            .bind(username || "")
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
            username: user.username
          },
          200,
          {
            "set-cookie":
              sessionCookie(token)
          }
        );

      }


      // =========================
      // LOGOUT
      // =========================

      if (
        request.method === "POST" &&
        path === "/api/logout"
      ) {

        const token =
          getSessionToken(request);


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


      // =========================
      // CURRENT USER
      // =========================

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
              authenticated: false
            },
            401
          );

        }


        if (
          session.role === "admin"
        ) {

          return json({
            authenticated: true,
            role: "admin",
            username: "admin"
          });

        }


        const user =
          await env.DB.prepare(`
            SELECT username
            FROM users
            WHERE id = ?
          `)
            .bind(session.user_id)
            .first();


        return json({
          authenticated: true,
          role: "user",
          username:
            user?.username || "user"
        });

      }


      // =========================
      // USER MESSAGES
      // =========================

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
            .bind(session.user_id)
            .all();


        return json({
          messages:
            rows.results || []
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
        } = await request.json();


        if (
          typeof body !== "string" ||
          !body.trim() ||
          body.length > MAX_MESSAGE
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


      // =========================
      // ADMIN USERS
      // =========================

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
              created_at
            FROM users
            WHERE role = 'user'
            ORDER BY username ASC
          `)
            .all();


        return json({
          users:
            rows.results || []
        });

      }


      // =========================
      // ADMIN READ MESSAGES
      // =========================

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
          !Number.isInteger(userId) ||
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
            .bind(userId)
            .all();


        return json({
          messages:
            rows.results || []
        });

      }


      // =========================
      // ADMIN SEND MESSAGE
      // =========================

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
        } = await request.json();


        const userId =
          Number(user_id);


        if (
          !Number.isInteger(userId) ||
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
          typeof body !== "string" ||
          !body.trim() ||
          body.length > MAX_MESSAGE
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
            .bind(userId)
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


      return new Response(
        "Not Found",
        {
          status: 404
        }
      );


    } catch (error) {

      console.error(error);

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