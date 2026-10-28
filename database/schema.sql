-- ================================================================
-- CrimeWatch — Standalone MySQL Schema
-- MySQL 8.0+ on its own dedicated server
-- Run: mysql -h <DB_HOST> -u root -p < schema.sql
-- ================================================================

CREATE DATABASE IF NOT EXISTS crimewatch
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE crimewatch;

-- ── USERS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            CHAR(36)     NOT NULL DEFAULT (UUID()),
  email         VARCHAR(255) NOT NULL,
  name          VARCHAR(255) NOT NULL,
  role          ENUM('public','officer','admin') NOT NULL DEFAULT 'public',
  password_hash VARCHAR(255) NOT NULL,
  public_key    TEXT         NULL     COMMENT 'Client ECDH public key PEM for E2E key exchange',
  is_active     TINYINT(1)   NOT NULL DEFAULT 1,
  last_login_at DATETIME     NULL,
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_email (email),
  KEY idx_role (role),
  KEY idx_active (is_active)
) ENGINE=InnoDB;

-- ── REPORTS ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
  id                CHAR(36)      NOT NULL DEFAULT (UUID()),
  client_id         VARCHAR(128)  NOT NULL COMMENT 'Device-generated ID for deduplication',

  -- E2E encrypted payload (AES-256-GCM, key wrapped with server RSA public key)
  encrypted_payload LONGTEXT      NOT NULL COMMENT 'Base64 AES-GCM ciphertext of full report JSON',
  encryption_iv     VARCHAR(64)   NOT NULL COMMENT 'Base64 GCM IV (12 bytes)',
  encryption_tag    VARCHAR(64)   NOT NULL COMMENT 'Base64 GCM auth tag (16 bytes)',
  wrapped_key       TEXT          NOT NULL COMMENT 'Base64 RSA-OAEP wrapped AES-256 key',

  -- Unencrypted metadata (needed for server-side filtering — never contains PII)
  severity          ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  incident_type     VARCHAR(100)  NOT NULL,
  status            ENUM('received','reviewing','investigating','resolved','closed') NOT NULL DEFAULT 'received',
  is_anonymous      TINYINT(1)    NOT NULL DEFAULT 1,

  -- Location (plaintext for geospatial queries)
  latitude          DECIMAL(10,7) NULL,
  longitude         DECIMAL(10,7) NULL,
  location_label    VARCHAR(255)  NULL,

  -- Relations
  submitted_by      CHAR(36)      NULL COMMENT 'NULL = unauthenticated submission',
  assigned_officer  CHAR(36)      NULL,

  -- Timestamps
  client_created_at DATETIME      NOT NULL COMMENT 'Timestamp from device clock',
  received_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  UNIQUE KEY uq_client_id (client_id),
  KEY idx_status   (status),
  KEY idx_severity (severity),
  KEY idx_type     (incident_type),
  KEY idx_received (received_at DESC),
  KEY idx_location (latitude, longitude),
  FOREIGN KEY fk_submitter (submitted_by)   REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY fk_officer   (assigned_officer) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ── MEDIA FILES ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS media_files (
  id               CHAR(36)      NOT NULL DEFAULT (UUID()),
  report_id        CHAR(36)      NOT NULL,
  original_name    VARCHAR(255)  NOT NULL,
  stored_name      VARCHAR(255)  NOT NULL COMMENT 'UUID-based filename on disk',
  mime_type        VARCHAR(100)  NOT NULL,
  file_size_bytes  INT UNSIGNED  NOT NULL DEFAULT 0,
  storage_path     VARCHAR(512)  NOT NULL COMMENT 'Absolute path on dedicated file storage',
  file_key_enc     TEXT          NULL     COMMENT 'Per-file AES key wrapped with report key',
  checksum_sha256  CHAR(64)      NULL     COMMENT 'SHA-256 of plaintext file for integrity',
  uploaded_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_media_report (report_id),
  FOREIGN KEY fk_media_report (report_id) REFERENCES reports(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ── OFFICER NOTES ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS officer_notes (
  id          CHAR(36)  NOT NULL DEFAULT (UUID()),
  report_id   CHAR(36)  NOT NULL,
  officer_id  CHAR(36)  NOT NULL,
  note        TEXT      NOT NULL,
  created_at  DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_notes_report (report_id),
  FOREIGN KEY fk_note_report  (report_id)  REFERENCES reports(id) ON DELETE CASCADE,
  FOREIGN KEY fk_note_officer (officer_id) REFERENCES users(id)   ON DELETE CASCADE
) ENGINE=InnoDB;

-- ── STATUS HISTORY ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS status_history (
  id          CHAR(36)    NOT NULL DEFAULT (UUID()),
  report_id   CHAR(36)    NOT NULL,
  changed_by  CHAR(36)    NULL,
  old_status  VARCHAR(50) NULL,
  new_status  VARCHAR(50) NOT NULL,
  note        TEXT        NULL,
  changed_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_history_report (report_id),
  FOREIGN KEY fk_hist_report (report_id) REFERENCES reports(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ── AUDIT LOG ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id     CHAR(36)        NULL,
  action      VARCHAR(100)    NOT NULL,
  resource    VARCHAR(100)    NULL,
  resource_id VARCHAR(128)    NULL,
  ip_address  VARCHAR(45)     NULL,
  user_agent  VARCHAR(512)    NULL,
  payload     JSON            NULL,
  created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_audit_user   (user_id),
  KEY idx_audit_action (action),
  KEY idx_audit_time   (created_at DESC)
) ENGINE=InnoDB;

-- ── REFRESH TOKENS ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          CHAR(36)     NOT NULL DEFAULT (UUID()),
  user_id     CHAR(36)     NOT NULL,
  token_hash  VARCHAR(255) NOT NULL COMMENT 'SHA-256 of the raw token',
  device_info VARCHAR(255) NULL,
  expires_at  DATETIME     NOT NULL,
  revoked     TINYINT(1)   NOT NULL DEFAULT 0,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_token_hash (token_hash),
  KEY idx_rt_user    (user_id),
  KEY idx_rt_expires (expires_at),
  FOREIGN KEY fk_rt_user (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ── SYNC QUEUE TRACKING ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS sync_log (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  client_id   VARCHAR(128)    NOT NULL,
  report_id   CHAR(36)        NULL,
  device_id   VARCHAR(255)    NULL,
  ip_address  VARCHAR(45)     NULL,
  sync_result ENUM('created','duplicate','failed') NOT NULL,
  synced_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_sync_client (client_id),
  KEY idx_sync_time   (synced_at DESC)
) ENGINE=InnoDB;

-- ── NOTIFICATIONS ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
  id          CHAR(36)     NOT NULL DEFAULT (UUID()),
  user_id     CHAR(36)     NOT NULL,
  report_id   CHAR(36)     NULL,
  type        VARCHAR(50)  NOT NULL,
  title       VARCHAR(255) NOT NULL,
  body        TEXT         NOT NULL,
  is_read     TINYINT(1)   NOT NULL DEFAULT 0,
  sent_push   TINYINT(1)   NOT NULL DEFAULT 0,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_notif_user   (user_id),
  KEY idx_notif_unread (user_id, is_read),
  FOREIGN KEY fk_notif_user   (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
  FOREIGN KEY fk_notif_report (report_id) REFERENCES reports(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ── SEED USERS ────────────────────────────────────────────────
-- Passwords: public123 / officer123 / admin123 (bcrypt $2b$ cost 12)
-- CHANGE BEFORE PRODUCTION
INSERT IGNORE INTO users (id, email, name, role, password_hash) VALUES
  (UUID(), 'public@crimewatch.ke',  'Public User',   'public',  '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/uVmGm6.'),
  (UUID(), 'officer@crimewatch.ke', 'Officer Kamau', 'officer', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/uVmGm6.'),
  (UUID(), 'admin@crimewatch.ke',   'Admin Wanjiku', 'admin',   '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/uVmGm6.');
