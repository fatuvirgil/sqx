<?php
/**
 * Test endpoint for Firebird error-based SQL injection
 * Tests: CAST errors, LIST errors
 */

header('Content-Type: application/json');

// Firebird connection
$db_host = getenv('DB_HOST') ?: 'firebird';
$db_name = getenv('DB_NAME') ?: '/firebird/data/security.fdb';
$db_user = getenv('DB_USER') ?: 'sqx_test';
$db_pass = getenv('DB_PASS') ?: 'sqx_pass';

try {
    // Firebird DSN format
    $dsn = "firebird:dbname=$db_host:$db_name;charset=UTF8";
    $pdo = new PDO($dsn, $db_user, $db_pass);
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
