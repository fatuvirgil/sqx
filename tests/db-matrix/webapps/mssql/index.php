<?php
/**
 * MSSQL sqli-labs vulnerable application
 * Port: 8143
 */

header('Content-Type: text/html; charset=utf-8');

$db_host = getenv('DB_HOST') ?: 'mssql-2019';
$db_port = getenv('DB_PORT') ?: '1433';
$db_name = getenv('DB_NAME') ?: 'security';
$db_user = getenv('DB_USER') ?: 'sa';
$db_pass = getenv('DB_PASS') ?: 'SqxTestPass123!';

try {
    $pdo = new PDO("sqlsrv:Server=$db_host,$db_port;Database=$db_name", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // Fallback to ODBC if sqlsrv not available
    try {
        $pdo = new PDO("odbc:Driver={ODBC Driver 17 for SQL Server};Server=$db_host,$db_port;Database=$db_name;UID=$db_user;PWD=$db_pass");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e2) {
        die("Database connection failed: " . $e->getMessage() . " / " . $e2->getMessage());
    }
}

$lesson = $_GET['lesson'] ?? 'Less-1';
$id = $_GET['id'] ?? '1';

switch ($lesson) {
    case 'Less-1':
        mssql_error_based($pdo, $id, "'");
        break;
    case 'Less-2':
        mssql_error_based($pdo, $id, "");
        break;
    case 'Less-5':
        mssql_boolean_blind($pdo, $id, "'");
        break;
    case 'Less-9':
        mssql_time_based($pdo, $id, "'");
        break;
    default:
        mssql_show_index();
}

function mssql_error_based($pdo, $id, $quote) {
    // VULNERABLE: String concatenation
    $sql = "SELECT TOP 1 * FROM users WHERE id = $quote$id$quote";
    
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
        echo "MSSQL Error: " . $e->getMessage();
    }
}

function mssql_boolean_blind($pdo, $id, $quote) {
    $sql = "SELECT TOP 1 * FROM users WHERE id = $quote$id$quote";
    
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

function mssql_time_based($pdo, $id, $quote) {
    // WAITFOR DELAY for time-based
    $sql = "SELECT TOP 1 * FROM users WHERE id = $quote$id$quote";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        echo $row ? "<h2>User Found</h2>" : "<h2>User Not Found</h2>";
    } catch (PDOException $e) {
        echo "Error";
    }
}

function mssql_show_index() {
    echo "<h1>SQX DB Matrix - MSSQL Test Application</h1>";
    echo "<p>Available lessons:</p>";
    echo "<ul>";
    echo "<li><a href='?lesson=Less-1&id=1'>Less-1: Error-based</a></li>";
    echo "<li><a href='?lesson=Less-5&id=1'>Less-5: Boolean blind</a></li>";
    echo "<li><a href='?lesson=Less-9&id=1'>Less-9: Time-based (WAITFOR)</a></li>";
    echo "</ul>";
}
?>
