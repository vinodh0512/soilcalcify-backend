-- 001_profile_core_up.sql
-- Adds enhanced profile fields to users and backfills names

ALTER TABLE `users`
  ADD COLUMN `first_name` VARCHAR(50) NOT NULL DEFAULT '',
  ADD COLUMN `last_name` VARCHAR(50) NOT NULL DEFAULT '',
  ADD COLUMN `phone` VARCHAR(20) NULL,
  ADD COLUMN `company` VARCHAR(100) NULL,
  ADD COLUMN `title` VARCHAR(100) NULL,
  ADD COLUMN `bio` TEXT NULL;

-- Composite index and unique phone
ALTER TABLE `users` ADD INDEX `idx_users_name` (`first_name`, `last_name`);
ALTER TABLE `users` ADD UNIQUE KEY `users_phone_unique` (`phone`);

-- Checks (require MySQL 8.0.16+)
ALTER TABLE `users` ADD CONSTRAINT `chk_phone_format` CHECK (phone IS NULL OR phone REGEXP '^\+[1-9][0-9]{1,14}$');
ALTER TABLE `users` ADD CONSTRAINT `chk_email_format` CHECK (email REGEXP '^[^\s@]+@[^\s@]+\.[^\s@]+$');
-- Removed avatar size check; avatar upload feature discontinued.

-- Backfill first/last from name
UPDATE `users`
SET `first_name` = IF(INSTR(`name`, ' ') > 0, SUBSTRING_INDEX(`name`, ' ', 1), `name`),
    `last_name` = IF(INSTR(`name`, ' ') > 0, SUBSTRING_INDEX(`name`, ' ', -1), '')
WHERE `first_name` = '' OR `last_name` = '';