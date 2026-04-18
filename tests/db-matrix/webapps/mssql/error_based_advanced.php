<?php
/**
 * Test endpoint for MSSQL error-based SQL injection
 * Tests: CONVERT overflow, CAST errors
 */

header('Content-Type: application/json');

// MSSQL connection via ODBC
$db_host = getenv('DB_HOST') ?: 'mssql-2019';
$db_port = getenv('DB_PORT') ?: '1433';
$db_name = getenv('DB_NAME') ?: 'security';
$db_user = getenv('DB_USER') ?: 'sa';
$db_pass = getenv('DB_PASS') ?: 'YourStrong@Passw0rd';

try {
    $pdo = new PDO("sqlsrv:Server=$db_host,$db_port;Database=$db_name", $db_user, $db_pass);
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
