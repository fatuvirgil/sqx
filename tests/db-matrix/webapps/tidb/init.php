<?php
// Initialize TiDB schema
$db_host = getenv('DB_HOST') ?: 'tidb';
$db_port = getenv('DB_PORT') ?: '4000';
$db_user = getenv('DB_USER') ?: 'root';

try {
    // Connect without database
    $pdo = new PDO("mysql:host=$db_host;port=$db_port;charset=utf8mb4", $db_user, '');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create database
    $pdo->exec("CREATE DATABASE IF NOT EXISTS security");
    echo "Database created\n";
    
    // Use database and create table
    $pdo->exec("USE security");
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY,
        username VARCHAR(100),
        password VARCHAR(100),
        email VARCHAR(100)
    )");
    echo "Table created\n";
    
    // Insert data
    $pdo->exec("INSERT INTO users VALUES 
        (1, 'Dumb', 'Dumb', 'dumb@test.com'),
        (2, 'Angelina', 'test', 'angelina@test.com')
        ON DUPLICATE KEY UPDATE id=id");
    echo "Data inserted\n";
    
    echo "✅ TiDB initialized!";
} catch (PDOException $e) {
    echo "Error: " . $e->getMessage();
}
