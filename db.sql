CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255),
  role ENUM('user','admin') DEFAULT 'user',
  subscription_expiry DATETIME,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS accounts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  provider VARCHAR(50) NOT NULL,           -- 'youtube'
  label VARCHAR(255),
  access_token TEXT,
  refresh_token TEXT,
  scope TEXT,
  token_type VARCHAR(50),
  expiry_date BIGINT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS jobs (
  id CHAR(36) PRIMARY KEY,
  user_id INT NOT NULL,
  account_id INT,
  title VARCHAR(255),
  description TEXT,
  privacy ENUM('public','unlisted','private') DEFAULT 'unlisted',
  filepath TEXT,
  rtmp TEXT,
  broadcast_id VARCHAR(255),
  stream_id VARCHAR(255),
  status VARCHAR(50),
  schedule_time DATETIME,
  auto_start TINYINT DEFAULT 0,
  created_at DATETIME,
  started_at DATETIME,
  ended_at DATETIME,
  logs JSON,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS settings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  key_name VARCHAR(100) UNIQUE,
  value TEXT
);

CREATE TABLE IF NOT EXISTS payments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  paket ENUM('weekly','monthly') NOT NULL,
  amount INT NOT NULL,
  status ENUM('pending','paid','failed') DEFAULT 'pending',
  qris_payload TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  paid_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
