-- init/postgres/init.sql - Schema inițială PostgreSQL pentru teste false positive

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
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
('Eve', 'eve@example.com', 'passworddef')
ON CONFLICT DO NOTHING;

-- Funcție pentru teste (echivalent stored procedure)
CREATE OR REPLACE FUNCTION get_user_by_id(user_id INT)
RETURNS TABLE(id INT, name VARCHAR, email VARCHAR, password VARCHAR, created_at TIMESTAMP) AS $$
BEGIN
    RETURN QUERY SELECT * FROM users WHERE users.id = user_id;
END;
$$ LANGUAGE plpgsql;

-- Tabel suplimentar pentru teste
CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
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
(4, 'Headphones', 149.99)
ON CONFLICT DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO testuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO testuser;
