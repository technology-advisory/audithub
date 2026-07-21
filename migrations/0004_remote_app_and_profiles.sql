PRAGMA foreign_keys = ON;

ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN title TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN photo TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN all_clients INTEGER NOT NULL DEFAULT 1 CHECK (all_clients IN (0, 1));

CREATE TABLE IF NOT EXISTS app_state (
  id TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_user_clients_user_id ON user_clients(user_id);
CREATE INDEX IF NOT EXISTS idx_user_clients_client_id ON user_clients(client_id);
