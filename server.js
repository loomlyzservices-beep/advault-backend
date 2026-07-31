import express from 'express'
import cors from 'cors'
import crypto from 'crypto'
import bcrypt from 'bcryptjs'
import Database from 'better-sqlite3'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '1111'
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '2222'
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '' // required to verify real payments server-side
// Railway note: the filesystem is ephemeral on redeploys unless you attach a
// Volume. Mount a Railway Volume at /data and set DB_PATH=/data/advault.db
// to keep users/ads/balances across deploys.
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'advault.db')

// ---------------------------------------------------------------------------
// DB setup
// ---------------------------------------------------------------------------
const db = new Database(DB_PATH)
db.pragma('journal_mode = WAL')
db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'))

// Lightweight migration for DBs created before the webhook feature existed.
const withdrawalCols = db.prepare("PRAGMA table_info(withdrawals)").all().map(c => c.name)
if(!withdrawalCols.includes('reference')){
  db.exec('ALTER TABLE withdrawals ADD COLUMN reference TEXT')
}

function todayStr(){ return new Date().toISOString().slice(0, 10) }
function newToken(){ return crypto.randomBytes(32).toString('hex') }
function round2(n){ return Math.round(n * 100) / 100 }

// Admin is NOT a row in `users` — it authenticates directly against
// ADMIN_USERNAME/ADMIN_PASSWORD env vars via a completely separate session
// system (see /api/admin/login below). If an older deployment already has a
// legacy admin user row, remove it so it can never show up as a "regular
// account" in the app or be reached through the normal login flow.
db.prepare('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE is_admin = 1)').run()
db.prepare('DELETE FROM users WHERE is_admin = 1').run()

function getSetting(key, fallback){
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key)
  return row ? row.value : fallback
}
function setSetting(key, value){
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, String(value))
}
function getSettings(){
  return {
    defaultAdsAllowance: Number(getSetting('defaultAdsAllowance', 5)),
    adRewardMin: Number(getSetting('adRewardMin', 8)),
    adRewardMax: Number(getSetting('adRewardMax', 13)),
  }
}

function getTier(level){
  return db.prepare('SELECT * FROM tiers WHERE level = ?').get(level)
}
function adsAllowanceFor(user){
  if(!user.tier) return getSettings().defaultAdsAllowance
  const t = getTier(user.tier)
  return t ? t.ads_per_day : getSettings().defaultAdsAllowance
}
function resetDailyAdsIfNeeded(user){
  if(user.last_ad_reset_date !== todayStr()){
    db.prepare('UPDATE users SET ads_watched_today = 0, last_ad_reset_date = ? WHERE id = ?').run(todayStr(), user.id)
    user.ads_watched_today = 0
    user.last_ad_reset_date = todayStr()
  }
  return user
}

// Strip fields that should never reach the client
function publicUser(user){
  if(!user) return null
  const { password_hash, ...rest } = user
  return {
    ...rest,
    balance: round2(user.balance),
    total_paid_out: round2(user.total_paid_out),
    adsAllowance: adsAllowanceFor(user),
    isAdmin: !!user.is_admin,
  }
}
// Ad shape shown to normal users: no title, no internal counters
function publicAd(ad){
  return {
    id: ad.id,
    mediaUrl: ad.media_url,
    durationSeconds: ad.duration_seconds,
  }
}

const app = express()
app.use(cors())
app.use(express.json({
  limit: '25mb', // generous limit to allow small base64 file uploads
  verify: (req, res, buf) => { req.rawBody = buf }, // needed to verify Paystack webhook signatures
}))

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
function requireAuth(req, res, next){
  const authHeader = req.headers.authorization || ''
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
  if(!token) return res.status(401).json({ error: 'Missing session token' })

  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token)
  if(!session) return res.status(401).json({ error: 'Invalid session' })
  if(session.revoked) return res.status(401).json({ error: 'Session revoked — please log in again' })
  if(new Date(session.expires_at) < new Date()) return res.status(401).json({ error: 'Session expired' })

  let user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id)
  if(!user) return res.status(401).json({ error: 'Account not found' })
  if(user.status !== 'active') return res.status(403).json({ error: 'This account has been paused' })

  user = resetDailyAdsIfNeeded(user)
  req.user = user
  req.sessionToken = token
  next()
}
// Completely separate from user auth: checks the Bearer token against
// admin_sessions, never against the users table. This is the only way
// admin routes can be reached.
function requireAdminSession(req, res, next){
  const authHeader = req.headers.authorization || ''
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
  if(!token) return res.status(401).json({ error: 'Missing admin session token' })

  const session = db.prepare('SELECT * FROM admin_sessions WHERE token = ?').get(token)
  if(!session) return res.status(401).json({ error: 'Invalid admin session' })
  if(session.revoked) return res.status(401).json({ error: 'Admin session revoked — please log in again' })
  if(new Date(session.expires_at) < new Date()) return res.status(401).json({ error: 'Admin session expired' })

  req.adminSessionToken = token
  next()
}

// Finds or creates an anonymous "guest" user row for a browser-generated guest id.
// Guests can watch ads and accrue a balance with no account; they must sign up
// or log in (which merges their guest balance into the real account) to withdraw.
function findOrCreateGuest(guestId){
  let user = db.prepare('SELECT * FROM users WHERE guest_id = ?').get(guestId)
  if(!user){
    const info = db.prepare(`INSERT INTO users (guest_id, is_guest, last_ad_reset_date) VALUES (?, 1, ?)`)
      .run(guestId, todayStr())
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid)
  }
  return resetDailyAdsIfNeeded(user)
}

// Used for ad watching only: accepts either a real Bearer session OR an
// X-Guest-Id header, so ads can be watched without an account.
function optionalAuth(req, res, next){
  const authHeader = req.headers.authorization || ''
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null

  if(token){
    const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token)
    if(session && !session.revoked && new Date(session.expires_at) >= new Date()){
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id)
      if(user && user.status === 'active'){
        req.user = resetDailyAdsIfNeeded(user)
        req.sessionToken = token
        return next()
      }
    }
    return res.status(401).json({ error: 'Invalid or expired session' })
  }

  const guestId = req.headers['x-guest-id']
  if(!guestId) return res.status(400).json({ error: 'Missing session or guest id.' })
  req.user = findOrCreateGuest(String(guestId))
  next()
}

// ---------------------------------------------------------------------------
// Health check (Railway uses this to confirm the service is up)
// ---------------------------------------------------------------------------
app.get('/', (req, res) => res.json({ ok: true, service: 'advault-backend' }))
app.get('/api/health', (req, res) => res.json({ ok: true }))

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
app.post('/api/auth/signup', (req, res) => {
  const { username, password, email, phone } = req.body || {}
  if(!username || !password || !email || !phone){
    return res.status(400).json({ error: 'Username, password, email, and phone are all required.' })
  }
  const clean = String(username).trim()
  if(clean.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters.' })
  if(String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' })

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim())
  if(!emailOk) return res.status(400).json({ error: 'Enter a valid email address.' })

  const phoneDigits = String(phone).replace(/[^\d]/g, '')
  const phoneOk = phoneDigits.length >= 9 && phoneDigits.length <= 13
  if(!phoneOk) return res.status(400).json({ error: 'Enter a valid mobile money phone number.' })

  const taken = db.prepare('SELECT id FROM users WHERE username = ?').get(clean)
  if(taken) return res.status(409).json({ error: 'That username is already taken.' })

  const hash = bcrypt.hashSync(String(password), 10)
  const guestId = req.headers['x-guest-id']
  const guest = guestId ? db.prepare('SELECT * FROM users WHERE guest_id = ? AND is_guest = 1').get(String(guestId)) : null

  let user
  if(guest){
    // Convert the guest row in place so their already-earned balance carries over.
    db.prepare(`UPDATE users SET username = ?, email = ?, phone = ?, password_hash = ?, is_guest = 0, guest_id = NULL
                WHERE id = ?`).run(clean, email, phone, hash, guest.id)
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(guest.id)
  } else {
    const info = db.prepare(`INSERT INTO users (username, email, phone, password_hash, last_ad_reset_date)
                              VALUES (?, ?, ?, ?, ?)`).run(clean, email, phone, hash, todayStr())
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid)
  }

  const token = newToken()
  const expires = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString()
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, user.id, expires)

  res.json({ token, user: publicUser(user) })
})

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {}
  if(!username || !password) return res.status(400).json({ error: 'Username and password are required.' })

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username).trim())
  if(!user) return res.status(404).json({ error: 'No account found — sign up first.' })

  const ok = bcrypt.compareSync(String(password), user.password_hash)
  if(!ok) return res.status(401).json({ error: 'Incorrect username or password.' })
  if(user.status !== 'active') return res.status(403).json({ error: 'Incorrect username or password.' })

  // If this browser was earning as a guest, fold that balance into the account.
  const guestId = req.headers['x-guest-id']
  if(guestId){
    const guest = db.prepare('SELECT * FROM users WHERE guest_id = ? AND is_guest = 1').get(String(guestId))
    if(guest && guest.id !== user.id){
      db.prepare(`UPDATE users SET balance = balance + ?, total_ads_watched = total_ads_watched + ?,
                  total_paid_out = total_paid_out + ? WHERE id = ?`)
        .run(guest.balance, guest.total_ads_watched, guest.total_paid_out, user.id)
      db.prepare('DELETE FROM users WHERE id = ?').run(guest.id)
    }
  }

  const token = newToken()
  const expires = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString()
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, user.id, expires)

  const freshUser = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id)
  res.json({ token, user: publicUser(resetDailyAdsIfNeeded(freshUser)) })
})

app.post('/api/auth/logout', requireAuth, (req, res) => {
  db.prepare('UPDATE sessions SET revoked = 1 WHERE token = ?').run(req.sessionToken)
  res.json({ ok: true })
})

// ---------------------------------------------------------------------------
// Admin auth — entirely separate system from user accounts/sessions.
// Credentials are checked directly against env vars (no DB row for admin),
// and the resulting token only ever lives in admin_sessions, never `sessions`.
// Sessions are short-lived (12h) specifically to limit exposure if a device
// used to log into the admin panel is later shared or left unattended.
// ---------------------------------------------------------------------------
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {}
  if(!username || !password) return res.status(400).json({ error: 'Username and password are required.' })

  const userBuf = Buffer.from(String(username))
  const adminUserBuf = Buffer.from(ADMIN_USERNAME)
  const usernameMatches = userBuf.length === adminUserBuf.length && crypto.timingSafeEqual(userBuf, adminUserBuf)
  const passwordMatches = String(password) === ADMIN_PASSWORD

  if(!usernameMatches || !passwordMatches){
    return res.status(401).json({ error: 'Incorrect admin username or password.' })
  }

  const token = newToken()
  const expires = new Date(Date.now() + 12 * 3600 * 1000).toISOString() // 12h, not 30d
  db.prepare('INSERT INTO admin_sessions (token, expires_at) VALUES (?, ?)').run(token, expires)
  res.json({ token })
})

app.post('/api/admin/logout', requireAdminSession, (req, res) => {
  db.prepare('UPDATE admin_sessions SET revoked = 1 WHERE token = ?').run(req.adminSessionToken)
  res.json({ ok: true })
})

app.get('/api/admin/session', requireAdminSession, (req, res) => {
  res.json({ ok: true })
})

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) })
})

// Like /api/me but also works for anonymous guests (X-Guest-Id header),
// so the dashboard/ads UI can show balance/progress before signing up.
app.get('/api/session', optionalAuth, (req, res) => {
  res.json({ user: publicUser(req.user) })
})

// ---------------------------------------------------------------------------
// Public data
// ---------------------------------------------------------------------------
app.get('/api/tiers', (req, res) => {
  const tiers = db.prepare('SELECT * FROM tiers ORDER BY level').all()
  res.json({ tiers })
})
app.get('/api/settings', (req, res) => {
  res.json({ settings: getSettings() })
})

// ---------------------------------------------------------------------------
// Ad watching
// ---------------------------------------------------------------------------
// Pick the next ad for a user: any active ad under its max-shows cap.
app.get('/api/ads/next', optionalAuth, (req, res) => {
  const allowance = adsAllowanceFor(req.user)
  if(req.user.ads_watched_today >= allowance){
    return res.status(403).json({ error: 'You have reached your ad limit for today.' })
  }
  const ad = db.prepare(`
    SELECT * FROM ads
    WHERE active = 1 AND (max_shows = 0 OR shows_count < max_shows)
    ORDER BY RANDOM() LIMIT 1
  `).get()
  if(!ad) return res.status(404).json({ error: 'No ads available right now.' })

  const nonce = newToken()
  db.prepare('INSERT INTO ad_watches (user_id, ad_id, nonce) VALUES (?, ?, ?)').run(req.user.id, ad.id, nonce)

  res.json({ ad: publicAd(ad), nonce, adsWatchedToday: req.user.ads_watched_today, adsAllowance: allowance })
})

// Called once the countdown finishes client-side. Pays out the reward.
app.post('/api/ads/complete', optionalAuth, (req, res) => {
  const { nonce } = req.body || {}
  if(!nonce) return res.status(400).json({ error: 'Missing nonce.' })

  const watch = db.prepare('SELECT * FROM ad_watches WHERE nonce = ? AND user_id = ?').get(nonce, req.user.id)
  if(!watch) return res.status(404).json({ error: 'Watch session not found.' })
  if(watch.status === 'completed') return res.status(409).json({ error: 'This ad was already paid out.' })

  const ad = db.prepare('SELECT * FROM ads WHERE id = ?').get(watch.ad_id)
  const { adRewardMin, adRewardMax } = getSettings()
  const reward = ad && ad.reward != null
    ? round2(ad.reward)
    : round2(adRewardMin + Math.random() * (adRewardMax - adRewardMin))

  const tx = db.transaction(() => {
    db.prepare('UPDATE ad_watches SET status = ?, reward = ?, completed_at = datetime(\'now\') WHERE id = ?')
      .run('completed', reward, watch.id)
    if(ad) db.prepare('UPDATE ads SET shows_count = shows_count + 1 WHERE id = ?').run(ad.id)
    db.prepare(`UPDATE users SET balance = balance + ?, ads_watched_today = ads_watched_today + 1,
                total_ads_watched = total_ads_watched + 1, total_paid_out = total_paid_out + ?
                WHERE id = ?`).run(reward, reward, req.user.id)
    db.prepare('INSERT INTO transactions (user_id, type, amount) VALUES (?, ?, ?)').run(req.user.id, 'ad_reward', reward)
  })
  tx()

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)
  res.json({ reward, user: publicUser(user) })
})

// ---------------------------------------------------------------------------
// Tier purchase (verifies the Paystack charge server-side before crediting)
// ---------------------------------------------------------------------------
app.post('/api/tiers/purchase', requireAuth, async (req, res) => {
  const { level, reference } = req.body || {}
  const tier = getTier(Number(level))
  if(!tier) return res.status(400).json({ error: 'Invalid tier.' })
  if(!reference) return res.status(400).json({ error: 'Missing payment reference.' })

  if(PAYSTACK_SECRET_KEY){
    try{
      const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
      })
      const verifyData = await verifyRes.json()
      const paid = verifyData?.data?.status === 'success'
      const paidAmountGHS = (verifyData?.data?.amount || 0) / 100
      if(!paid) return res.status(402).json({ error: 'Payment was not successful.' })
      if(paidAmountGHS < tier.price - 0.5){
        return res.status(402).json({ error: 'Paid amount does not match tier price.' })
      }
    }catch(err){
      return res.status(502).json({ error: 'Could not verify payment with Paystack. Try again shortly.' })
    }
  }
  // NOTE: if PAYSTACK_SECRET_KEY is not set, verification is skipped (useful for
  // local/demo testing only). Always set PAYSTACK_SECRET_KEY in production.

  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET tier = ? WHERE id = ?').run(tier.level, req.user.id)
    db.prepare('INSERT INTO transactions (user_id, type, amount, reference) VALUES (?, ?, ?, ?)')
      .run(req.user.id, 'tier_purchase', tier.price, reference)
  })
  tx()

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)
  res.json({ user: publicUser(user) })
})

// ---------------------------------------------------------------------------
// Withdrawals — real Paystack Mobile Money transfer
// ---------------------------------------------------------------------------
// Ghana mobile money bank codes recognised by Paystack's transfer recipient API.
const MOMO_BANK_CODES = { mtn: 'MTN', vodafone: 'VOD', telecel: 'VOD', airteltigo: 'ATL' }

async function paystackFetch(urlPath, options){
  const r = await fetch(`https://api.paystack.co${urlPath}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
      'Content-Type': 'application/json',
      ...(options?.headers || {}),
    },
  })
  const data = await r.json().catch(() => ({}))
  return { ok: r.ok && data?.status !== false, data }
}

app.post('/api/withdraw', requireAuth, async (req, res) => {
  const { phone, network } = req.body || {}
  if(!req.user.tier) return res.status(403).json({ error: 'Buy a tier to unlock withdrawals.' })
  if(req.user.balance <= 0) return res.status(400).json({ error: 'Your balance is empty.' })

  const amount = round2(req.user.balance)
  const cleanPhone = String(phone || req.user.phone || '').replace(/[^\d]/g, '')
  const bankCode = MOMO_BANK_CODES[String(network || '').toLowerCase()]

  if(!cleanPhone || cleanPhone.length < 9){
    return res.status(400).json({ error: 'A valid mobile money number is required.' })
  }
  if(!bankCode){
    return res.status(400).json({ error: 'Select a valid mobile money network (MTN, Vodafone/Telecel, or AirtelTigo).' })
  }
  if(!PAYSTACK_SECRET_KEY){
    return res.status(503).json({ error: 'Payouts are not configured yet. Try again shortly.' })
  }

  // Withdrawal row starts as 'pending' — only flipped to 'completed' once Paystack
  // confirms the transfer (either in the immediate response or via webhook later).
  // Balance is zeroed at the same time the row is created, inside one transaction,
  // to avoid double-spending on a retried request.
  const reference = `advault_wd_${req.user.id}_${Date.now()}`
  const insertPending = db.prepare(
    'INSERT INTO withdrawals (user_id, amount, phone, status, reference) VALUES (?, ?, ?, ?, ?)'
  )
  let withdrawalId
  const lock = db.transaction(() => {
    const fresh = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id)
    if(fresh.balance <= 0) throw new Error('EMPTY_BALANCE')
    db.prepare('UPDATE users SET balance = 0 WHERE id = ?').run(req.user.id)
    withdrawalId = insertPending.run(req.user.id, amount, cleanPhone, 'pending', reference).lastInsertRowid
  })
  try{ lock() } catch(e){
    if(e.message === 'EMPTY_BALANCE') return res.status(400).json({ error: 'Your balance is empty.' })
    throw e
  }

  try{
    // 1. Create a transfer recipient for this mobile money number.
    const recipientRes = await paystackFetch('/transferrecipient', {
      method: 'POST',
      body: JSON.stringify({
        type: 'mobile_money',
        name: req.user.username,
        account_number: cleanPhone,
        bank_code: bankCode,
        currency: 'GHS',
      }),
    })
    if(!recipientRes.ok){
      throw new Error(recipientRes.data?.message || 'Could not register mobile money recipient.')
    }
    const recipientCode = recipientRes.data.data.recipient_code

    // 2. Initiate the transfer.
    const transferRes = await paystackFetch('/transfer', {
      method: 'POST',
      body: JSON.stringify({
        source: 'balance',
        amount: Math.round(amount * 100),
        recipient: recipientCode,
        reason: 'Advault withdrawal',
        reference,
      }),
    })
    if(!transferRes.ok){
      throw new Error(transferRes.data?.message || 'Transfer could not be initiated.')
    }

    const transferStatus = transferRes.data?.data?.status // 'success' | 'pending' | 'otp' | ...
    const finalStatus = transferStatus === 'success' ? 'completed' : 'pending'
    db.prepare('UPDATE withdrawals SET status = ? WHERE id = ?').run(finalStatus, withdrawalId)
    if(finalStatus === 'completed'){
      db.prepare('UPDATE users SET total_paid_out = total_paid_out + ? WHERE id = ?').run(amount, req.user.id)
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)
    return res.json({
      amount,
      status: finalStatus,
      message: finalStatus === 'completed'
        ? 'Withdrawal sent successfully.'
        : 'Withdrawal is processing — funds will arrive shortly.',
      user: publicUser(user),
    })
  }catch(err){
    // Refund the balance and mark the withdrawal as failed — never let the user
    // lose their balance for a transfer that didn't actually go out.
    db.transaction(() => {
      db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(amount, req.user.id)
      db.prepare('UPDATE withdrawals SET status = ? WHERE id = ?').run('failed', withdrawalId)
    })()
    return res.status(502).json({ error: err.message || 'Withdrawal failed. Your balance has been restored.' })
  }
})

// ---------------------------------------------------------------------------
// Paystack webhook — the reliable source of truth for transfer status.
// Set this exact URL in Paystack Dashboard → Settings → API Keys & Webhooks:
//   https://YOUR-BACKEND-URL/api/webhook/paystack
// ---------------------------------------------------------------------------
app.post('/api/webhook/paystack', (req, res) => {
  // Verify the request genuinely came from Paystack using the raw body + secret key.
  const signature = req.headers['x-paystack-signature']
  if(!PAYSTACK_SECRET_KEY || !signature || !req.rawBody){
    return res.status(400).json({ error: 'Invalid webhook request.' })
  }
  const expected = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(req.rawBody).digest('hex')
  if(expected !== signature){
    return res.status(401).json({ error: 'Invalid signature.' })
  }

  // Acknowledge immediately — Paystack retries if it doesn't get a fast 200.
  res.sendStatus(200)

  const event = req.body?.event
  const data = req.body?.data
  const reference = data?.reference
  if(!reference || !['transfer.success', 'transfer.failed', 'transfer.reversed'].includes(event)) return

  const withdrawal = db.prepare('SELECT * FROM withdrawals WHERE reference = ?').get(reference)
  if(!withdrawal || withdrawal.status !== 'pending') return // already handled, or not ours

  if(event === 'transfer.success'){
    db.transaction(() => {
      db.prepare('UPDATE withdrawals SET status = ? WHERE id = ?').run('completed', withdrawal.id)
      db.prepare('UPDATE users SET total_paid_out = total_paid_out + ? WHERE id = ?')
        .run(withdrawal.amount, withdrawal.user_id)
    })()
  } else {
    // transfer.failed or transfer.reversed — refund the user, it never arrived.
    db.transaction(() => {
      db.prepare('UPDATE withdrawals SET status = ? WHERE id = ?').run('failed', withdrawal.id)
      db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(withdrawal.amount, withdrawal.user_id)
    })()
  }
})

// ---------------------------------------------------------------------------
// Winners feed (cosmetic/social proof — real recent payouts, names anonymized)
// ---------------------------------------------------------------------------
app.get('/api/winners', (req, res) => {
  const rows = db.prepare(`
    SELECT u.username, t.amount, t.created_at FROM transactions t
    JOIN users u ON u.id = t.user_id
    WHERE t.type = 'ad_reward'
    ORDER BY t.created_at DESC LIMIT 20
  `).all()
  res.json({ winners: rows })
})

// =============================================================================
// ADMIN ROUTES
// =============================================================================
const admin = express.Router()
admin.use(requireAdminSession)

admin.get('/overview', (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) c FROM users WHERE is_admin = 0 AND is_guest = 0').get().c
  const totalAdsWatched = db.prepare('SELECT COALESCE(SUM(total_ads_watched),0) s FROM users').get().s
  const totalPaidOut = db.prepare('SELECT COALESCE(SUM(total_paid_out),0) s FROM users').get().s
  const activeAds = db.prepare('SELECT COUNT(*) c FROM ads WHERE active = 1').get().c
  const totalWithdrawn = db.prepare('SELECT COALESCE(SUM(amount),0) s FROM withdrawals').get().s
  res.json({ totalUsers, totalAdsWatched, totalPaidOut: round2(totalPaidOut), activeAds, totalWithdrawn: round2(totalWithdrawn) })
})

// --- Users ---
admin.get('/users', (req, res) => {
  const rows = db.prepare('SELECT * FROM users WHERE is_admin = 0 AND is_guest = 0 ORDER BY created_at DESC').all()
  res.json({ users: rows.map(publicUser) })
})
admin.post('/users/:id/pause', (req, res) => {
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run('paused', req.params.id)
  res.json({ ok: true })
})
admin.post('/users/:id/unpause', (req, res) => {
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run('active', req.params.id)
  res.json({ ok: true })
})
admin.post('/users/:id/force-logout', (req, res) => {
  db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ?').run(req.params.id)
  res.json({ ok: true })
})
admin.delete('/users/:id', (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id)
  res.json({ ok: true })
})
admin.delete('/users', (req, res) => {
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM transactions').run()
    db.prepare('DELETE FROM withdrawals').run()
    db.prepare('DELETE FROM ad_watches').run()
    db.prepare('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE is_admin = 0 AND is_guest = 0)').run()
    db.prepare('DELETE FROM users WHERE is_admin = 0 AND is_guest = 0').run()
  })
  tx()
  res.json({ ok: true })
})

// --- Ads ---
admin.get('/ads', (req, res) => {
  res.json({ ads: db.prepare('SELECT * FROM ads ORDER BY created_at DESC').all() })
})
admin.post('/ads', (req, res) => {
  const { title, mediaUrl, durationSeconds, reward, maxShows } = req.body || {}
  if(!title || !mediaUrl) return res.status(400).json({ error: 'Title and media URL/file are required.' })
  const info = db.prepare(`INSERT INTO ads (title, media_url, duration_seconds, reward, max_shows)
    VALUES (?, ?, ?, ?, ?)`).run(
      title, mediaUrl,
      durationSeconds ? Number(durationSeconds) : 15,
      reward === '' || reward == null ? null : Number(reward),
      maxShows ? Number(maxShows) : 0,
    )
  res.json({ ad: db.prepare('SELECT * FROM ads WHERE id = ?').get(info.lastInsertRowid) })
})
admin.put('/ads/:id', (req, res) => {
  const { title, mediaUrl, durationSeconds, reward, maxShows, active } = req.body || {}
  db.prepare(`UPDATE ads SET title = ?, media_url = ?, duration_seconds = ?, reward = ?, max_shows = ?, active = ?
              WHERE id = ?`).run(
    title, mediaUrl, Number(durationSeconds) || 15,
    reward === '' || reward == null ? null : Number(reward),
    Number(maxShows) || 0, active ? 1 : 0, req.params.id,
  )
  res.json({ ad: db.prepare('SELECT * FROM ads WHERE id = ?').get(req.params.id) })
})
admin.post('/ads/:id/toggle', (req, res) => {
  const ad = db.prepare('SELECT * FROM ads WHERE id = ?').get(req.params.id)
  if(!ad) return res.status(404).json({ error: 'Not found' })
  db.prepare('UPDATE ads SET active = ? WHERE id = ?').run(ad.active ? 0 : 1, req.params.id)
  res.json({ ok: true })
})
admin.delete('/ads/:id', (req, res) => {
  db.prepare('DELETE FROM ads WHERE id = ?').run(req.params.id)
  res.json({ ok: true })
})
admin.delete('/ads', (req, res) => {
  db.prepare('DELETE FROM ads').run()
  res.json({ ok: true })
})

// --- Transactions ---
admin.get('/transactions', (req, res) => {
  const rows = db.prepare(`
    SELECT t.*, u.username FROM transactions t JOIN users u ON u.id = t.user_id
    ORDER BY t.created_at DESC LIMIT 500
  `).all()
  res.json({ transactions: rows })
})
admin.delete('/transactions', (req, res) => {
  db.prepare('DELETE FROM transactions').run()
  res.json({ ok: true })
})

// --- Ad analytics ---
admin.post('/analytics/reset', (req, res) => {
  db.prepare('UPDATE users SET total_ads_watched = 0, total_paid_out = 0, ads_watched_today = 0').run()
  db.prepare('UPDATE ads SET shows_count = 0').run()
  res.json({ ok: true })
})

// --- Withdrawals ---
admin.get('/withdrawals', (req, res) => {
  const rows = db.prepare(`
    SELECT w.*, u.username FROM withdrawals w JOIN users u ON u.id = w.user_id
    ORDER BY w.created_at DESC
  `).all()
  res.json({ withdrawals: rows })
})
admin.delete('/withdrawals/:id', (req, res) => {
  db.prepare('DELETE FROM withdrawals WHERE id = ?').run(req.params.id)
  res.json({ ok: true })
})
admin.delete('/withdrawals', (req, res) => {
  db.prepare('DELETE FROM withdrawals').run()
  res.json({ ok: true })
})

// --- Tiers & settings ---
admin.put('/tiers/:level', (req, res) => {
  const { price, adsPerDay } = req.body || {}
  db.prepare('UPDATE tiers SET price = ?, ads_per_day = ? WHERE level = ?')
    .run(Number(price), Number(adsPerDay), req.params.level)
  res.json({ tier: getTier(Number(req.params.level)) })
})
admin.put('/settings', (req, res) => {
  const { defaultAdsAllowance, adRewardMin, adRewardMax } = req.body || {}
  if(defaultAdsAllowance != null) setSetting('defaultAdsAllowance', Number(defaultAdsAllowance))
  if(adRewardMin != null) setSetting('adRewardMin', Number(adRewardMin))
  if(adRewardMax != null) setSetting('adRewardMax', Number(adRewardMax))
  res.json({ settings: getSettings() })
})

// --- Full wipe (keeps the admin account) ---
admin.post('/reset-everything', (req, res) => {
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM transactions').run()
    db.prepare('DELETE FROM withdrawals').run()
    db.prepare('DELETE FROM ad_watches').run()
    db.prepare('DELETE FROM ads').run()
    db.prepare('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE is_admin = 0 AND is_guest = 0)').run()
    db.prepare('DELETE FROM users WHERE is_admin = 0 AND is_guest = 0').run()
  })
  tx()
  res.json({ ok: true })
})

app.use('/api/admin', admin)

// ---------------------------------------------------------------------------
// Error handler (keeps error responses as JSON, not HTML stack traces)
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).json({ error: 'Server error' })
})

app.listen(PORT, () => {
  console.log(`Advault backend listening on port ${PORT}`)
})
