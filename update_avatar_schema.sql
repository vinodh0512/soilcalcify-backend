-- Add avatar_url column to users table if it doesn't exist
ALTER TABLE users ADD COLUMN avatar_url VARCHAR(1024) NULL;

-- Create user_avatars table if it doesn't exist
CREATE TABLE IF NOT EXISTS user_avatars (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  path VARCHAR(1024) NOT NULL,
  mime VARCHAR(64) NOT NULL,
  size BIGINT UNSIGNED NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX idx_user_avatars_user_created (user_id, created_at),
  CONSTRAINT fk_user_avatars_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;