-- PostgreSQL sqli-labs schema

-- Create tables
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100) DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS emails (
    id SERIAL PRIMARY KEY,
    email_id VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS referers (
    id SERIAL PRIMARY KEY,
    referer VARCHAR(255) DEFAULT NULL,
    ip_address VARCHAR(50) DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS uagents (
    id SERIAL PRIMARY KEY,
    uagent VARCHAR(255) DEFAULT NULL,
    ip_address VARCHAR(50) DEFAULT NULL,
    username VARCHAR(100) DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS secret (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    secret VARCHAR(255) DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    product_name VARCHAR(200) NOT NULL,
    price DECIMAL(10,2) DEFAULT 0.00,
    description TEXT
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT DEFAULT 1,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create a function for version extraction testing
CREATE OR REPLACE FUNCTION get_db_version()
RETURNS TEXT AS $$
BEGIN
    RETURN version();
END;
$$ LANGUAGE plpgsql;

-- Insert flags
INSERT INTO secret (username, password, secret) VALUES 
('admin', 'supersecret123', 'FLAG{postgres_extraction_success}'),
('postgres', 'postgres', 'FLAG{db_admin_access}')
ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret;
