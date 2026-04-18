-- MSSQL sqli-labs schema

-- Create tables
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='users' AND xtype='U')
CREATE TABLE users (
    id INT IDENTITY(1,1) PRIMARY KEY,
    username NVARCHAR(100) NOT NULL,
    password NVARCHAR(100) NOT NULL,
    email NVARCHAR(100) NULL
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='emails' AND xtype='U')
CREATE TABLE emails (
    id INT IDENTITY(1,1) PRIMARY KEY,
    email_id NVARCHAR(100) NOT NULL
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='referers' AND xtype='U')
CREATE TABLE referers (
    id INT IDENTITY(1,1) PRIMARY KEY,
    referer NVARCHAR(255) NULL,
    ip_address NVARCHAR(50) NULL
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='uagents' AND xtype='U')
CREATE TABLE uagents (
    id INT IDENTITY(1,1) PRIMARY KEY,
    uagent NVARCHAR(255) NULL,
    ip_address NVARCHAR(50) NULL,
    username NVARCHAR(100) NULL
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='secret' AND xtype='U')
CREATE TABLE secret (
    id INT IDENTITY(1,1) PRIMARY KEY,
    username NVARCHAR(100) NOT NULL,
    password NVARCHAR(100) NOT NULL,
    secret NVARCHAR(255) NULL
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='products' AND xtype='U')
CREATE TABLE products (
    id INT IDENTITY(1,1) PRIMARY KEY,
    product_name NVARCHAR(200) NOT NULL,
    price DECIMAL(10,2) DEFAULT 0.00,
    description NVARCHAR(MAX) NULL
);

IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='orders' AND xtype='U')
CREATE TABLE orders (
    id INT IDENTITY(1,1) PRIMARY KEY,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT DEFAULT 1,
    order_date DATETIME DEFAULT GETDATE()
);

-- Enable xp_cmdshell for advanced testing (disabled by default)
-- sp_configure 'show advanced options', 1; RECONFIGURE;
-- sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Insert flags
IF NOT EXISTS (SELECT 1 FROM secret WHERE username = 'admin')
INSERT INTO secret (username, password, secret) VALUES 
('admin', 'supersecret123', 'FLAG{mssql_extraction_success}'),
('sa', 'SqxTestPass123!', 'FLAG{sysadmin_access}');
