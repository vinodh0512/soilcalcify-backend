-- Adds profile-related fields and indexes to the users table.
-- Run after database and base users table exist.

-- Adjust database name if needed; uncomment to use explicitly
-- USE `u352373478_SoilCalcify`;

ALTER TABLE `users`
  ADD COLUMN `bio` TEXT NULL,
  ADD COLUMN `location` VARCHAR(255) NULL,
  ADD COLUMN `website_url` VARCHAR(255) NULL,
  ADD COLUMN `twitter_url` VARCHAR(255) NULL,
  ADD COLUMN `linkedin_url` VARCHAR(255) NULL,
  ADD COLUMN `github_url` VARCHAR(255) NULL,
  ADD COLUMN `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;

-- Index to accelerate profile fetches and cache invalidation
ALTER TABLE `users` ADD INDEX `idx_users_updated_at` (`updated_at`);