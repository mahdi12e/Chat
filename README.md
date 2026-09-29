# Private Chat (Cloudflare Worker + D1)

A minimal dark private messaging site. Visitors register, then chat privately with the
administrator. Everything (frontend, API, sessions) runs in one Cloudflare Worker with a D1 database.

Files: `worker.js` (the whole app), `schema.sql` (optional, tables are auto-created),
`wrangler.toml` (only needed for command-line deploys).

## Deploy from an Android phone (Cloudflare dashboard, no computer)

Use Chrome. If the dashboard looks cramped, open the Chrome menu and tick "Desktop site".
Cloudflare renames menu items now and then; the names below may differ slightly.

### 1. Create a Cloudflare account
1. Go to https://dash.cloudflare.com/sign-up
2. Enter your email and a password, then confirm the verification email.

### 2. Create a Worker
1. In the dashboard menu open **Workers & Pages** (under Compute).
2. Tap **Create application** > **Start with Hello World!**
3. Name it `private-chat` and tap **Deploy**.
4. Tap **Edit code**. Select all the sample code, delete it, and paste the entire contents of `worker.js`.
5. Tap **Deploy**.

### 3. Create a D1 database
1. Dashboard menu > **Storage & databases** > **D1 SQL Database**.
2. Tap **Create Database**, name it `private-chat-db`, and create it.
3. Optional: open the database > **Console**, paste `schema.sql`, and run it.
   You can skip this: the Worker creates the tables itself on first use.

### 4 and 5. Connect D1 to the Worker (the DB binding)
1. Open your Worker > **Settings** > **Bindings** > **Add**.
2. Choose **D1 database**.
3. **Variable name** must be exactly `DB`. Select `private-chat-db`.
4. Save/Deploy.

### 6. Create the ADMIN_PASSWORD secret
1. Worker > **Settings** > **Variables and Secrets** > **Add**.
2. Type: **Secret**. Name: `ADMIN_PASSWORD`. Value: a long, unique password (16+ characters).
3. Save/Deploy. Never put this password in the code.

### 7 and 8. Deploy and find your URL
Deploy the Worker (step 2.5 or after any settings change). Your address is on the Worker's
overview page, shaped like `https://private-chat.YOUR-SUBDOMAIN.workers.dev`. Open it in Chrome.

### 9. Create a normal user
Open the URL, tap **Create an account**, choose a username (3-30 letters, numbers, underscore)
and a password (8+ characters), then tap **Create account**. You are logged in and see the chat.
The username `admin` is reserved.

### 10. Log in as administrator
Log out, then log in with username `admin` and the `ADMIN_PASSWORD` you set. You see the
Admin Panel: a user list (on top on phones), the selected conversation, and a reply box.

### 11. Test private messaging
1. As the normal user, send "hello".
2. Log out, log in as `admin`, select that user, and you should see "hello".
3. Reply. Log out, log in as the user again, and the reply appears (the page also refreshes every 5 seconds).
4. To confirm privacy, create a second user: it sees an empty conversation, never the first user's messages.

### 12. Update the Worker later
Worker > **Edit code**, paste the new `worker.js`, **Deploy**. Your D1 data, bindings and secret are kept.

## Deploy with the command line instead (Termux or a computer)
1. `npx wrangler d1 create private-chat-db` and copy the `database_id` into `wrangler.toml`
   in place of `REPLACE_WITH_YOUR_D1_DATABASE_ID`.
2. `npx wrangler d1 execute private-chat-db --remote --file=schema.sql` (optional).
3. `npx wrangler secret put ADMIN_PASSWORD`
4. `npx wrangler deploy`

Note: `wrangler.toml` is not used by the dashboard method; there you set the binding in the dashboard.

## Security notes
- Passwords: PBKDF2-SHA-256, 100,000 iterations (the maximum Workers allows), random salt per user.
- Sessions: 256-bit random token in an HttpOnly, Secure, SameSite=Strict cookie (`__Host-` prefixed),
  7-day expiry. Only a SHA-256 hash of the token is stored in D1. Nothing is kept in localStorage.
- Every private endpoint checks the session server-side. A user's messages are always read and written
  using the user id from the session, never one supplied by the browser. Admin endpoints require the admin role.
- The admin password lives only in the `ADMIN_PASSWORD` secret. Changing the secret changes the password.
- XSS: messages are inserted with `textContent` only, and a nonce-based Content-Security-Policy is sent.
- CSRF: SameSite=Strict, Origin/Sec-Fetch-Site checks, and JSON-only request bodies.
- Users are limited to 20 messages per minute. To slow password guessing, add a Cloudflare
  rate-limiting rule for `/api/login` in the dashboard (Security > WAF > Rate limiting rules).
- Messages are stored in D1 unencrypted, so the account owner and anyone with dashboard access can read them.

## Troubleshooting
- "The D1 binding named DB is missing": redo step 4/5; the variable name must be exactly `DB`.
- "The ADMIN_PASSWORD secret is not configured": redo step 6 and deploy again.
- Login says session ended repeatedly: cookies must be allowed, and use the https:// address.