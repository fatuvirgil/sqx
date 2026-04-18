<?php
/**
 * Advanced injection contexts for testing new boundaries
 * - LIKE clause injection
 * - IN clause injection  
 * - ORDER BY injection
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

$test = $_GET['test'] ?? 'index';
$param = $_GET['param'] ?? '';

switch ($test) {
    case 'like':
        // VULNERABLE: LIKE clause injection
        // SQL: SELECT * FROM users WHERE username LIKE '%$param%'
        $sql = "SELECT * FROM users WHERE username LIKE '%$param%' LIMIT 5";
        echo "<!-- Query: $sql -->";
        try {
            $stmt = $pdo->query($sql);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($rows) {
                echo "<h2>Search Results</h2>";
                foreach ($rows as $row) {
                    echo "User: " . htmlspecialchars($row['username']) . "<br>";
                }
            } else {
                echo "<h2>No Results</h2>";
            }
        } catch (PDOException $e) {
            echo "SQL Error: " . $e->getMessage();
        }
        break;
        
    case 'in':
        // VULNERABLE: IN clause injection
        // SQL: SELECT * FROM users WHERE id IN ($param)
        $sql = "SELECT * FROM users WHERE id IN ($param) LIMIT 5";
        echo "<!-- Query: $sql -->";
        try {
            $stmt = $pdo->query($sql);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($rows) {
                echo "<h2>Users Found</h2>";
                foreach ($rows as $row) {
                    echo "ID: " . htmlspecialchars($row['id']) . " - User: " . htmlspecialchars($row['username']) . "<br>";
                }
            } else {
                echo "<h2>No Users</h2>";
            }
        } catch (PDOException $e) {
            echo "SQL Error: " . $e->getMessage();
        }
        break;
        
    case 'orderby':
        // VULNERABLE: ORDER BY injection
        // SQL: SELECT * FROM users ORDER BY $param
        $sql = "SELECT * FROM users ORDER BY $param LIMIT 5";
        echo "<!-- Query: $sql -->";
        try {
            $stmt = $pdo->query($sql);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            echo "<h2>Users (Ordered)</h2>";
            foreach ($rows as $row) {
                echo "ID: " . htmlspecialchars($row['id']) . " - User: " . htmlspecialchars($row['username']) . "<br>";
            }
        } catch (PDOException $e) {
            echo "SQL Error: " . $e->getMessage();
        }
        break;
        
    default:
        echo "<h1>Advanced Injection Contexts</h1>";
        echo "<ul>";
        echo "<li><a href='?test=like&param=admin'>LIKE clause injection</a></li>";
        echo "<li><a href='?test=in&param=1,2,3'>IN clause injection</a></li>";
        echo "<li><a href='?test=orderby&param=id'>ORDER BY injection</a></li>";
        echo "</ul>";
}
?>
