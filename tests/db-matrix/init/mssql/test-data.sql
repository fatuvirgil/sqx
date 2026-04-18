-- MSSQL test data

IF NOT EXISTS (SELECT 1 FROM users WHERE username = 'Dumb')
INSERT INTO users (username, password, email) VALUES
('Dumb', 'Dumb', 'dumb@sqli-labs.com'),
('Angelina', 'I-kill-you', 'angelina@sqli-labs.com'),
('Dummy', 'p@ssword', 'dummy@sqli-labs.com'),
('secure', 'crappy', 'secure@sqli-labs.com'),
('stupid', 'stupidity', 'stupid@sqli-labs.com'),
('superman', 'genious', 'superman@sqli-labs.com'),
('batman', 'mob!le', 'batman@sqli-labs.com'),
('admin', 'admin', 'admin@sqli-labs.com');

IF NOT EXISTS (SELECT 1 FROM emails WHERE email_id = 'Dumb@sqli-labs.com')
INSERT INTO emails (email_id) VALUES
('Dumb@sqli-labs.com'),
('Angel@sqli-labs.com'),
('Dummy@sqli-labs.com'),
('secure@sqli-labs.com'),
('stupid@sqli-labs.com'),
('superman@sqli-labs.com'),
('batman@sqli-labs.com'),
('admin@sqli-labs.com');

IF NOT EXISTS (SELECT 1 FROM products WHERE product_name = 'Laptop Dell XPS')
INSERT INTO products (product_name, price, description) VALUES
('Laptop Dell XPS', 1299.99, 'High-end business laptop'),
('MacBook Pro', 2499.00, 'Apple M2 chip laptop'),
('ThinkPad X1', 1899.50, 'Lenovo business laptop'),
('HP Spectre', 1399.99, 'Convertible 2-in-1 laptop'),
('ASUS ZenBook', 999.99, 'Ultrabook with OLED display'),
('Mouse Logitech', 49.99, 'Wireless ergonomic mouse'),
('Keyboard Mechanical', 129.99, 'Cherry MX switches'),
('Monitor 4K', 449.99, '27 inch 4K display'),
('Webcam HD', 79.99, '1080p webcam'),
('USB-C Hub', 39.99, '7-in-1 USB-C adapter');

IF NOT EXISTS (SELECT 1 FROM orders WHERE user_id = 1)
INSERT INTO orders (user_id, product_id, quantity) VALUES
(1, 1, 1),
(1, 6, 2),
(2, 2, 1),
(3, 3, 1),
(4, 4, 1),
(5, 5, 1),
(6, 7, 1),
(7, 8, 2),
(8, 1, 3),
(8, 6, 1);
