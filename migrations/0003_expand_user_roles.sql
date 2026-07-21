PRAGMA foreign_keys = OFF;

CREATE TABLE users_new (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  local_login TEXT NOT NULL UNIQUE,
  cloud_email TEXT UNIQUE,
  role TEXT NOT NULL CHECK (
    role IN (
      'admin',
      'lead-auditor',
      'auditor',
      'client',
      'read-only'
    )
  ),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'disabled')),
  password_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users_new (
  id,
  name,
  local_login,
  cloud_email,
  role,
  status,
  password_hash,
  created_at,
  updated_at
)
SELECT
  id,
  name,
  local_login,
  cloud_email,
  CASE
    WHEN role = 'readonly' THEN 'read-only'
    ELSE role
  END,
  status,
  password_hash,
  created_at,
  updated_at
FROM users;

DROP TABLE users;

ALTER TABLE users_new RENAME TO users;

CREATE INDEX IF NOT EXISTS idx_users_cloud_email
  ON users(cloud_email);

PRAGMA foreign_keys = ON;