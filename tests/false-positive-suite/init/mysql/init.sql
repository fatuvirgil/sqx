-- init/mysql/init.sql - Schema inițială MySQL pentru teste false positive

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (name, email, password) VALUES
('Alice', 'alice@example.com', 'password123'),
('Bob', 'bob@example.com', 'password456'),
('Charlie', 'charlie@example.com', 'password789'),
('Diana', 'diana@example.com', 'passwordabc'),
('Eve', 'eve@example.com', 'passworddef');

-- Stored procedure pentru teste
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS get_user_by_id(IN user_id INT)
BEGIN
    SELECT * FROM users WHERE id = user_id;
END //
DELIMITER ;

-- Tabel suplimentar pentru teste JOIN
CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product VARCHAR(100),
    amount DECIMAL(10,2),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO orders (user_id, product, amount) VALUES
(1, 'Laptop', 999.99),
(1, 'Mouse', 29.99),
(2, 'Keyboard', 79.99),
(3, 'Monitor', 299.99),
(4, 'Headphones', 149.99);

GRANT ALL PRIVILEGES ON testdb.* TO 'testuser'@'%';
FLUSH PRIVILEGES;
