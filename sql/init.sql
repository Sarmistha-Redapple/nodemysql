-- 1) Create database
CREATE DATABASE IF NOT EXISTS demo_app;
USE demo_app;

-- 2) Create table
CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(191) NOT NULL,
  phone VARCHAR(30) NULL,
  address VARCHAR(255) NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_users_email (email)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  token_hash VARCHAR(500) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_refresh_tokens_user_id (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- Named SQL blocks used by the Node app (loaded dynamically).
-- Format:
--   -- name: some/path
--   <single SQL statement>
-- ------------------------------------------------------------

-- name: schema/create_users_table
CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(191) NOT NULL,
  phone VARCHAR(30) NULL,
  address VARCHAR(255) NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_users_email (email)
)

-- name: schema/create_refresh_tokens_table
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  token_hash VARCHAR(500) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_refresh_tokens_user_id (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)

-- name: schema/refresh_tokens_dedupe
DELETE rt_old
FROM refresh_tokens rt_old
JOIN refresh_tokens rt_new
  ON rt_old.user_id = rt_new.user_id
 AND rt_old.id < rt_new.id

-- name: schema/refresh_tokens_add_unique_user_id
ALTER TABLE refresh_tokens
ADD UNIQUE KEY uniq_refresh_tokens_user_id (user_id)

-- name: queries/users/select_by_email
SELECT id, name, email, phone, address, password_hash, created_at
FROM users
WHERE email = ?
LIMIT 1

-- name: queries/users/insert
INSERT INTO users (name, email, phone, address, password_hash)
VALUES (?, ?, ?, ?, ?)

-- name: queries/users/select_by_id
SELECT id, name, email, phone, address, created_at
FROM users
WHERE id = ?

-- name: queries/users/select_all_desc
SELECT id, name, email, phone, address, created_at
FROM users
ORDER BY id DESC

-- name: queries/refresh_tokens/select_by_token
SELECT rt.id AS refresh_id, rt.user_id, u.id, u.name, u.email, u.phone, u.address, u.created_at
FROM refresh_tokens rt
JOIN users u ON u.id = rt.user_id
WHERE rt.token_hash = ?
  AND rt.expires_at > NOW()
LIMIT 1

-- name: queries/refresh_tokens/update_by_user_id
UPDATE refresh_tokens
SET token_hash = ?, expires_at = ?
WHERE user_id = ?

-- name: queries/refresh_tokens/insert
INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
VALUES (?, ?, ?)

-- name: queries/refresh_tokens/delete_by_token_hash
DELETE FROM refresh_tokens
WHERE token_hash = ?
