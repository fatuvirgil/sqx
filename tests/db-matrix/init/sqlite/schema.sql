-- SQLite sqli-labs schema

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS referers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referer TEXT DEFAULT NULL,
    ip_address TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS uagents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uagent TEXT DEFAULT NULL,
    ip_address TEXT DEFAULT NULL,
    username TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS secret (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    secret TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_name TEXT NOT NULL,
    price REAL DEFAULT 0.00,
    description TEXT
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER DEFAULT 1,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert flags
INSERT OR REPLACE INTO secret (id, username, password, secret) VALUES 
(1, 'admin', 'supersecret123', 'FLAG{sqlite_extraction_success}'),
(2, 'sqlite', 'sqlite', 'FLAG{file_db_access}');
