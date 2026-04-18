<?php
/**
 * Test endpoint for ClickHouse error-based SQL injection
 * Tests: CAST, toInt64 errors
 */

header('Content-Type: application/json');

// ClickHouse connection via HTTP interface
$db_host = getenv('DB_HOST') ?: 'clickhouse';
$db_port = getenv('DB_PORT') ?: '8123';
$db_name = getenv('DB_NAME') ?: 'security';
$db_user = getenv('DB_USER') ?: 'sqx_test';
$db_pass = getenv('DB_PASS') ?: 'sqx_pass';

$input = $_GET['id'] ?? '1';

// Intentionally vulnerable query - direct interpolation
// ClickHouse supports SQL-like syntax but with differences
$query = "SELECT * FROM users WHERE id = '$input' FORMAT JSON";

// Use HTTP interface for ClickHouse
$url = "http://$db_host:$db_port/?database=$db_name&user=$db_user&password=$db_pass";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $query);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curl_error = curl_error($ch);
curl_close($ch);

if ($curl_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Connection failed: ' . $curl_error, 'query' => $query]);
    exit;
}

// Check for ClickHouse error in response (ClickHouse returns errors in body with Code: X.)
if (strpos($response, 'Code:') !== false && strpos($response, 'DB::Exception:') !== false) {
    http_response_code(500);
    echo json_encode(['error' => $response, 'query' => $query]);
    exit;
}

echo json_encode(['response' => json_decode($response, true), 'query' => $query]);
