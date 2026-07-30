# Advault Backend

Express + SQLite API for Advault. Handles accounts, sessions, ad payouts, tier
purchases (verified against Paystack), withdrawals, and the full admin panel.

## Deploying to Railway

1. Push this folder to its own GitHub repo (or use `railway up` from inside it).
2. In Railway: **New Project → Deploy from GitHub repo** (or drag-and-drop this folder with the CLI).
3. Railway auto-detects Node via Nixpacks and runs `npm install && npm start`.
4. Under **Variables**, set:
   - `ADMIN_USERNAME` — the admin login username. Always set this explicitly in production.
   - `ADMIN_PASSWORD` — the admin login password. Always set this explicitly in production.
   - `PAYSTACK_SECRET_KEY` — your **secret** key from the Paystack dashboard (Settings → API Keys). Without this, tier purchases are NOT verified server-side — fine for testing, unsafe for real money.
5. Railway assigns a public URL like `https://advault-backend-production.up.railway.app`. Copy it — the frontend needs it.
6. **Persistence**: Railway's filesystem is wiped on every redeploy unless you attach a **Volume**. In your service → Settings → Volumes, mount a volume at `/data`, then set the variable `DB_PATH=/data/advault.db`. Without this, all users/balances reset on every deploy.

## Local development

```
npm install
npm start
```

Runs on `http://localhost:3000` by default. Copy `.env.example` to `.env` and fill in real values if you want to test Paystack verification locally (`node --env-file=.env server.js`, or use a tool like `dotenv-cli`).

## What's still simulated / needs finishing before real money moves

- **Withdrawals** (`POST /api/withdraw`) zero the user's balance and log a record, but do not actually send money. A real payout needs the Paystack **Transfers API** (create a transfer recipient, then initiate a transfer) using `PAYSTACK_SECRET_KEY` — that's a small addition to the `/api/withdraw` route once you're ready to test it with real Paystack transfer permissions enabled on your account.
- **Tier purchases** ARE verified server-side against Paystack if `PAYSTACK_SECRET_KEY` is set — this part is real.
- Passwords are hashed with bcrypt (real, production-safe).
- Sessions are random tokens stored in SQLite with expiry + revocation (used for force-logout).

## API summary

- `POST /api/auth/signup` `{ username, password, email, phone }`
- `POST /api/auth/login` `{ username, password }`
- `POST /api/auth/logout` (auth)
- `GET /api/me` (auth)
- `GET /api/tiers`, `GET /api/settings`, `GET /api/winners`
- `GET /api/ads/next` (auth) — issues a one-time nonce for the served ad
- `POST /api/ads/complete` `{ nonce }` (auth) — pays out the reward
- `POST /api/tiers/purchase` `{ level, reference }` (auth)
- `POST /api/withdraw` `{ phone }` (auth)
- `/api/admin/*` — all require an admin session (login as the admin user first). Covers users, ads, transactions, withdrawals, analytics reset, tier/settings edits, and full platform reset.
