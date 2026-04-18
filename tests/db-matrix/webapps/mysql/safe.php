<?php
/**
 * SAFE endpoints for false positive testing
 * Uses prepared statements (PDO prepare/execute)
 */

header('Content-Type: text/html; charset=utf-8');

$db_host = getenv('DB_HOST') ?: 'mysql-57';
$db_port = getenv('DB_PORT') ?: '3306';
$db_name = getenv('DB_NAME') ?: 'security';
$db_user = getenv('DB_USER') ?: 'sqx_test';
$db_pass = getenv('DB_PASS') ?: 'sqx_pass';

try {
    $pdo = new PDO("mysql:host=$db_host;port=$db_port;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

$test = $_GET['test'] ?? 'pdo';
$id = $_GET['id'] ?? '1';

switch ($test) {
    case 'pdo':
        // SAFE: PDO prepared statement with parameter binding
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? LIMIT 0,1");
        $stmt->execute([$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>User Details (SAFE PDO)</h2>";
            echo "ID: " . htmlspecialchars($row['id']) . "<br>";
            echo "Username: " . htmlspecialchars($row['username']) . "<br>";
        } else {
            echo "User not found";
        }
        break;
        
    case 'intval':
        // SAFE: Using intval() for numeric IDs
        $safe_id = intval($id);
        $stmt = $pdo->query("SELECT * FROM users WHERE id = $safe_id LIMIT 0,1");
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>User Details (SAFE intval)</h2>";
            echo "ID: " . htmlspecialchars($row['id']) . "<br>";
            echo "Username: " . htmlspecialchars($row['username']) . "<br>";
        } else {
            echo "User not found";
        }
        break;
        
    case 'numeric_check':
        // SAFE: Explicit numeric check
        if (!is_numeric($id)) {
            echo "Invalid ID (must be numeric)";
            break;
        }
        $stmt = $pdo->query("SELECT * FROM users WHERE id = $id LIMIT 0,1");
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>User Details (SAFE numeric check)</h2>";
            echo "ID: " . htmlspecialchars($row['id']) . "<br>";
            echo "Username: " . htmlspecialchars($row['username']) . "<br>";
        } else {
            echo "User not found";
        }
        break;
        
    default:
        echo "<h1>Safe Endpoints</h1>";
        echo "<ul>";
        echo "<li><a href='?test=pdo&id=1'>PDO Prepared Statement</a></li>";
        echo "<li><a href='?test=intval&id=1'>intval() Sanitization</a></li>";
        echo "<li><a href='?test=numeric_check&id=1'>Numeric Check</a></li>";
        echo "</ul>";
}
?>
