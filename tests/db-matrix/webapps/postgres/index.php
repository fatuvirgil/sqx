<?php
/**
 * PostgreSQL sqli-labs vulnerable application
 * Port: 8113
 */

header('Content-Type: text/html; charset=utf-8');

$db_host = getenv('DB_HOST') ?: 'postgres-13';
$db_port = getenv('DB_PORT') ?: '5432';
$db_name = getenv('DB_NAME') ?: 'security';
$db_user = getenv('DB_USER') ?: 'sqx_test';
$db_pass = getenv('DB_PASS') ?: 'sqx_pass';

try {
    $pdo = new PDO("pgsql:host=$db_host;port=$db_port;dbname=$db_name", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

$lesson = $_GET['lesson'] ?? 'Less-1';
$id = $_GET['id'] ?? '1';

switch ($lesson) {
    case 'Less-1':
        pg_error_based($pdo, $id, "'");
        break;
    case 'Less-2':
        pg_error_based($pdo, $id, "");
        break;
    case 'Less-5':
        pg_boolean_blind($pdo, $id, "'");
        break;
    case 'Less-9':
        pg_time_based($pdo, $id, "'");
        break;
    default:
        pg_show_index();
}

function pg_error_based($pdo, $id, $quote) {
    // VULNERABLE: String concatenation
    $sql = "SELECT * FROM users WHERE id = $quote$id$quote LIMIT 1";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>User Details</h2>";
            echo "ID: " . htmlspecialchars($row['id']) . "<br>";
            echo "Username: " . htmlspecialchars($row['username']) . "<br>";
            echo "Password: " . htmlspecialchars($row['password']) . "<br>";
        } else {
            echo "User not found";
        }
    } catch (PDOException $e) {
        echo "PostgreSQL Error: " . $e->getMessage();
    }
}

function pg_boolean_blind($pdo, $id, $quote) {
    $sql = "SELECT * FROM users WHERE id = $quote$id$quote LIMIT 1";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>User Found</h2>";
            echo "<img src='flag.jpg' alt='Found'>";
        } else {
            echo "<h2>User Not Found</h2>";
            echo "<img src='slap.jpg' alt='Not found'>";
        }
    } catch (PDOException $e) {
        echo "<h2>User Not Found</h2>";
    }
}

function pg_time_based($pdo, $id, $quote) {
    // pg_sleep() for time-based
    $sql = "SELECT * FROM users WHERE id = $quote$id$quote LIMIT 1";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        echo $row ? "<h2>User Found</h2>" : "<h2>User Not Found</h2>";
    } catch (PDOException $e) {
        echo "Error";
    }
}

function pg_show_index() {
    echo "<h1>SQX DB Matrix - PostgreSQL Test Application</h1>";
    echo "<p>Available lessons:</p>";
    echo "<ul>";
    echo "<li><a href='?lesson=Less-1&id=1'>Less-1: Error-based</a></li>";
    echo "<li><a href='?lesson=Less-5&id=1'>Less-5: Boolean blind</a></li>";
    echo "<li><a href='?lesson=Less-9&id=1'>Less-9: Time-based (pg_sleep)</a></li>";
    echo "</ul>";
}
?>
