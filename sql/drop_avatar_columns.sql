-- Drops all avatar-related columns from the users table
-- Run this if your database already has avatar fields and you want them removed

ALTER TABLE `users`
  DROP COLUMN `avatar_path`,
  DROP COLUMN `avatar_prev_path`,
  DROP COLUMN `avatar_mime`,
  DROP COLUMN `avatar_size`;

-- If you previously added encrypted avatar BLOB fields via migrations
ALTER TABLE `users`
  DROP COLUMN `avatar_blob`,
  DROP COLUMN `avatar_iv`,
  DROP COLUMN `avatar_tag`;