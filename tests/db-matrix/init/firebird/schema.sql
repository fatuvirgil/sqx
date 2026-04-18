-- Firebird Schema for SQL Injection Testing
-- Note: Firebird uses double quotes for identifiers and single quotes for strings

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(100),
    password VARCHAR(100),
    email VARCHAR(100)
);

-- Insert test data
INSERT INTO users (id, username, password, email) VALUES (1, 'Dumb', 'Dumb', 'dumb@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (2, 'Angelina', 'I-kill-you', 'angelina@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (3, 'Dummy', 'p@ssword', 'dummy@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (4, 'secure', 'crappy', 'secure@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (5, 'stupid', 'stupidity', 'stupid@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (6, 'superman', 'genious', 'superman@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (7, 'batman', 'mob!le', 'batman@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (8, 'admin', 'admin', 'admin@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (9, 'admin1', 'admin1', 'admin1@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (10, 'admin2', 'admin2', 'admin2@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (11, 'admin3', 'admin3', 'admin3@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (12, 'dhakkan', 'dumbo', 'dhakkan@sqli-labs.com');
INSERT INTO users (id, username, password, email) VALUES (13, 'admin4', 'admin4', 'admin4@sqli-labs.com');
