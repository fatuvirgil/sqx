-- MySQL sqli-labs schema
-- Compatible with MySQL 5.7, 8.0, and MariaDB 10.x

CREATE DATABASE IF NOT EXISTS security;
USE security;

-- Users table (target for injection)
CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100) DEFAULT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Emails table
CREATE TABLE IF NOT EXISTS emails (
    id INT NOT NULL AUTO_INCREMENT,
    email_id VARCHAR(100) NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Referers table
CREATE TABLE IF NOT EXISTS referers (
    id INT NOT NULL AUTO_INCREMENT,
    referer VARCHAR(255) DEFAULT NULL,
    ip_address VARCHAR(50) DEFAULT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- UAgents table
CREATE TABLE IF NOT EXISTS uagents (
    id INT NOT NULL AUTO_INCREMENT,
    uagent VARCHAR(255) DEFAULT NULL,
    ip_address VARCHAR(50) DEFAULT NULL,
    username VARCHAR(100) DEFAULT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Secret table (flag target)
CREATE TABLE IF NOT EXISTS secret (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    secret VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Products table
CREATE TABLE IF NOT EXISTS products (
    id INT NOT NULL AUTO_INCREMENT,
    product_name VARCHAR(200) NOT NULL,
    price DECIMAL(10,2) DEFAULT 0.00,
    description TEXT,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT DEFAULT 1,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create a flag for extraction testing
INSERT INTO secret (username, password, secret) VALUES 
('admin', 'supersecret123', 'FLAG{mysql_extraction_success}'),
('root', 'toor', 'FLAG{root_access_granted}')
ON DUPLICATE KEY UPDATE secret=VALUES(secret);
