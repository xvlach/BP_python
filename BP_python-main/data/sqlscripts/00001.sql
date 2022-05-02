-- Create Database and user
CREATE DATABASE IF NOT EXISTS archivationsystem;
CREATE USER IF NOT EXISTS 'ncadmin'@'localhost' IDENTIFIED BY 'ncadmin';
GRANT ALL PRIVILEGES ON archivationsystem.* TO 'ncadmin'@'localhost';
FLUSH PRIVILEGES;