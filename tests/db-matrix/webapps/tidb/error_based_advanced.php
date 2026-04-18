<?php
/**
 * Test endpoint for TiDB error-based SQL injection
 * TiDB is MySQL-compatible
 */

header('Content-Type: application/json');

// TiDB connection (MySQL protocol)
$db_host = getenv('DB_HOST') ?: 'tidb';
$db_port = getenv('DB_PORT') ?: '4000';
$db_name = getenv('DB_NAME') ?: 'security';
$db_user = getenv('DB_USER') ?: 'root';
$db_pass = getenv('DB_PASS') ?: '';

try {
    $pdo = new PDO("mysql:host=$db_host;port=$db_port;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    die(json_encode(['error' => 'Connection failed: ' . $e->getMessage()]));
}

$input = $_GET['id'] ?? '1';

// Intentionally vulnerable query
$query = "SELECT * FROM users WHERE id = '$input'";

try {
    $result = $pdo->query($query);
    $rows = $result->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode(['users' => $rows, 'query' => $query]);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage(), 'query' => $query]);
}
