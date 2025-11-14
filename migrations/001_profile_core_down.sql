-- 001_profile_core_down.sql
-- Reverts enhanced profile fields from users (drops columns, indexes, checks)

ALTER TABLE `users`
  DROP COLUMN `first_name`,
  DROP COLUMN `last_name`,
  DROP COLUMN `phone`,
  DROP COLUMN `company`,
  DROP COLUMN `title`,
  DROP COLUMN `bio`;

ALTER TABLE `users` DROP INDEX `idx_users_name`;
ALTER TABLE `users` DROP INDEX `users_phone_unique`;

ALTER TABLE `users` DROP CHECK `chk_phone_format`;
ALTER TABLE `users` DROP CHECK `chk_email_format`;