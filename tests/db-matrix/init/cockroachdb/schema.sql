-- CockroachDB Schema for SQL Injection Testing
-- PostgreSQL-compatible distributed SQL database

CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY,
    username VARCHAR(100),
    password VARCHAR(100),
    email VARCHAR(100)
);

-- Insert test data
INSERT INTO users (id, username, password, email) VALUES
    (1, 'Dumb', 'Dumb', 'dumb@sqli-labs.com'),
    (2, 'Angelina', 'I-kill-you', 'angelina@sqli-labs.com'),
    (3, 'Dummy', 'p@ssword', 'dummy@sqli-labs.com'),
    (4, 'secure', 'crappy', 'secure@sqli-labs.com'),
    (5, 'stupid', 'stupidity', 'stupid@sqli-labs.com'),
    (6, 'superman', 'genious', 'superman@sqli-labs.com'),
    (7, 'batman', 'mob!le', 'batman@sqli-labs.com'),
    (8, 'admin', 'admin', 'admin@sqli-labs.com'),
    (9, 'admin1', 'admin1', 'admin1@sqli-labs.com'),
    (10, 'admin2', 'admin2', 'admin2@sqli-labs.com'),
    (11, 'admin3', 'admin3', 'admin3@sqli-labs.com'),
    (12, 'dhakkan', 'dumbo', 'dhakkan@sqli-labs.com'),
    (13, 'admin4', 'admin4', 'admin4@sqli-labs.com')
ON CONFLICT (id) DO NOTHING;
