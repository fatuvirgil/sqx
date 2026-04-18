<?php
/**
 * SQLite sqli-labs vulnerable application
 * Port: 8190
 */

header('Content-Type: text/html; charset=utf-8');

$db_file = getenv('SQLITE_DB') ?: '/data/sqli-labs.db';

if (!file_exists($db_file)) {
    die("SQLite database not found at: $db_file");
}

try {
    $pdo = new PDO("sqlite:$db_file");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

$lesson = $_GET['lesson'] ?? 'Less-1';
$id = $_GET['id'] ?? '1';

switch ($lesson) {
    case 'Less-1':
        sqlite_error_based($pdo, $id, "'");
        break;
    case 'Less-2':
        sqlite_error_based($pdo, $id, "");
        break;
    case 'Less-5':
        sqlite_boolean_blind($pdo, $id, "'");
        break;
    case 'Less-9':
        sqlite_time_based($pdo, $id, "'");
        break;
    default:
        sqlite_show_index();
}

function sqlite_error_based($pdo, $id, $quote) {
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
        echo "SQLite Error: " . $e->getMessage();
    }
}

function sqlite_boolean_blind($pdo, $id, $quote) {
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

function sqlite_time_based($pdo, $id, $quote) {
    // randomblob(1000000000) for time delay in SQLite
    $sql = "SELECT * FROM users WHERE id = $quote$id$quote LIMIT 1";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        echo $row ? "<h2>User Found</h2>" : "<h2>User Not Found</h2>";
    } catch (PDOException $e) {
        echo "Error";
    }
}

function sqlite_show_index() {
    echo "<h1>SQX DB Matrix - SQLite Test Application</h1>";
    echo "<p>Available lessons:</p>";
    echo "<ul>";
    echo "<li><a href='?lesson=Less-1&id=1'>Less-1: Error-based</a></li>";
    echo "<li><a href='?lesson=Less-5&id=1'>Less-5: Boolean blind</a></li>";
    echo "<li><a href='?lesson=Less-9&id=1'>Less-9: Time-based (randomblob)</a></li>";
    echo "</ul>";
}
?>
