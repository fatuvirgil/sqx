<?php
/**
 * Test endpoint for H2 error-based SQL injection
 */

header('Content-Type: application/json');

// H2 connection (via PDO JDBC bridge or direct JDBC)
$db_host = getenv('DB_HOST') ?: 'h2';
$db_port = getenv('DB_PORT') ?: '1521';
$db_name = getenv('DB_NAME') ?: 'security';
$db_user = getenv('DB_USER') ?: 'sa';
$db_pass = getenv('DB_PASS') ?: '';

// H2 default is to create in-memory database if not exists
try {
    // H2 has JDBC URL format: jdbc:h2:tcp://host:port/mem:dbname
    // But PDO_ODBC might work
    $pdo = new PDO("odbc:DRIVER={H2 Driver};SERVER=$db_host;PORT=$db_port;DATABASE=$db_name", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    die(json_encode(['error' => 'Connection failed: ' . $e->getMessage()]));
}

$input = $_GET['id'] ?? '1';
$query = "SELECT * FROM users WHERE id = '$input'";

try {
    $result = $pdo->query($query);
    $rows = $result->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode(['users' => $rows, 'query' => $query]);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage(), 'query' => $query]);
}
