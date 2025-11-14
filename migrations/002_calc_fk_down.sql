-- 002_calc_fk_down.sql
-- Drops foreign key linking calculation_history.user_id to users.id

ALTER TABLE `calculation_history`
  DROP FOREIGN KEY `fk_calculation_user`;