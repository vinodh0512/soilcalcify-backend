-- Optional: Create a dedicated MySQL user for the application
-- Replace the username and password as needed

-- Create user (local-only)
CREATE USER IF NOT EXISTS 'soil_user'@'localhost' IDENTIFIED BY 'your_strong_password';

-- Grant privileges on the target database
GRANT ALL PRIVILEGES ON `u352373478_SoilCalcify`.* TO 'soil_user'@'localhost';

-- Apply privilege changes
FLUSH PRIVILEGES;