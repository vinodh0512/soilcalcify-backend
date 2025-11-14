-- 002_calc_fk_up.sql
-- Adds foreign key from calculation_history.user_id to users.id

ALTER TABLE `calculation_history`
  ADD CONSTRAINT `fk_calculation_user`
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
  ON DELETE CASCADE;