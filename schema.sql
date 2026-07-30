-- Advault database schema (SQLite)

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  email TEXT,
  phone TEXT,
  password_hash TEXT,
  balance REAL NOT NULL DEFAULT 0,
  tier INTEGER NOT NULL DEFAULT 0,
  ads_watched_today INTEGER NOT NULL DEFAULT 0,
  total_ads_watched INTEGER NOT NULL DEFAULT 0,
  total_paid_out REAL NOT NULL DEFAULT 0,
  last_ad_reset_date TEXT,
  status TEXT NOT NULL DEFAULT 'active',      -- 'active' | 'paused'
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_guest INTEGER NOT NULL DEFAULT 0,        -- 1 = anonymous browser session, no account yet
  guest_id TEXT UNIQUE,                       -- random id stored in the browser's localStorage
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,               -- admin-only label, never sent to non-admin clients
  media_url TEXT NOT NULL,           -- link or data: URI
  duration_seconds INTEGER NOT NULL DEFAULT 15,
  reward REAL,                       -- fixed reward; NULL = use the global random range
  max_shows INTEGER NOT NULL DEFAULT 0,  -- 0 = unlimited
  shows_count INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ad_watches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  ad_id INTEGER REFERENCES ads(id),
  nonce TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'started',   -- 'started' | 'completed' | 'expired'
  reward REAL,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS tiers (
  level INTEGER PRIMARY KEY,
  price REAL NOT NULL,
  ads_per_day INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  type TEXT NOT NULL,                 -- 'tier_purchase' | 'ad_reward'
  amount REAL NOT NULL,
  reference TEXT,
  status TEXT NOT NULL DEFAULT 'completed',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS withdrawals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount REAL NOT NULL,
  phone TEXT,
  status TEXT NOT NULL DEFAULT 'completed',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_watches_user ON ad_watches(user_id, started_at);
CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_withdrawals_user ON withdrawals(user_id, created_at);

-- Seed default tiers: level 1 = GHS 65, level 10 = GHS 250
INSERT OR IGNORE INTO tiers (level, price, ads_per_day) VALUES
  (1, 65.00, 10),
  (2, 85.50, 13),
  (3, 106.00, 16),
  (4, 126.50, 19),
  (5, 147.00, 22),
  (6, 167.50, 26),
  (7, 188.00, 30),
  (8, 208.50, 34),
  (9, 229.00, 37),
  (10, 250.00, 40);

-- Seed default settings
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('defaultAdsAllowance', '5'),
  ('adRewardMin', '8'),
  ('adRewardMax', '13');
