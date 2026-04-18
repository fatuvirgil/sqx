<?php
/**
 * MySQL sqli-labs vulnerable application
 * Port: 8057 (MySQL 5.7), 8080 (MySQL 8.0), 8010 (MariaDB)
 */

header('Content-Type: text/html; charset=utf-8');

// Database connection
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

$lesson = $_GET['lesson'] ?? 'Less-1';
$id = $_GET['id'] ?? '1';

// Lesson router
switch ($lesson) {
    case 'Less-1': // Error-based, single quotes
        less_error_based($pdo, $id, "'");
        break;
    case 'Less-2': // Error-based, integer
        less_error_based($pdo, $id, "");
        break;
    case 'Less-3': // Error-based, single quotes + parenthesis
        less_error_based($pdo, $id, "')");
        break;
    case 'Less-4': // Error-based, double quotes + parenthesis
        less_error_based($pdo, $id, '\")');
        break;
    case 'Less-5': // Boolean blind, single quotes
        less_boolean_blind($pdo, $id, "'");
        break;
    case 'Less-6': // Boolean blind, double quotes (MySQL treats " as identifier, not string!)
        // For proper double-quote injection test, use single quotes in SQL but test with double quote escaping
        less_boolean_blind_double_quote($pdo, $id);
        break;
    case 'Less-8': // Boolean blind (numeric in quotes)
        less_boolean_blind($pdo, $id, "'");
        break;
    case 'Less-9': // Time-based blind
        less_time_based($pdo, $id, "'");
        break;
    case 'Less-10': // Time-based blind, double quotes
        less_time_based($pdo, $id, '\"');
        break;
    default:
        show_index();
}

// ─────────────────────────────────────────────────────────────
// Lesson implementations
// ─────────────────────────────────────────────────────────────

function less_error_based($pdo, $id, $quote) {
    // VULNERABLE: Direct concatenation
    $sql = "SELECT * FROM users WHERE id = $quote$id$quote LIMIT 0,1";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>User Details</h2>";
            echo "ID: " . htmlspecialchars($row['id']) . "<br>";
            echo "Username: " . htmlspecialchars($row['username']) . "<br>";
            echo "Password: " . htmlspecialchars($row['password']) . "<br>";
            echo "Email: " . htmlspecialchars($row['email']) . "<br>";
        } else {
            echo "User not found";
        }
    } catch (PDOException $e) {
        // This exposes SQL errors - intentional vulnerability
        echo "SQL Error: " . $e->getMessage();
    }
}

function less_boolean_blind($pdo, $id, $quote) {
    // VULNERABLE: Direct concatenation, no error output
    $sql = "SELECT * FROM users WHERE id = $quote$id$quote LIMIT 0,1";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>User Found</h2>";
            echo "<img src='flag.jpg' alt='User avatar'>";
        } else {
            echo "<h2>User Not Found</h2>";
            echo "<img src='slap.jpg' alt='Not found'>";
        }
    } catch (PDOException $e) {
        // No error output - blind injection
        echo "<h2>User Not Found</h2>";
        echo "<img src='slap.jpg' alt='Not found'>";
    }
}

function less_boolean_blind_double_quote($pdo, $id) {
    // VULNERABLE: Double quote context (simulates ANSI_QUOTES mode or other DBs)
    // The SQL uses single quotes but we inject double quote to break out
    $sql = "SELECT * FROM users WHERE id = '$id' LIMIT 0,1";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>User Found</h2>";
            echo "<img src='flag.jpg' alt='User avatar'>";
        } else {
            echo "<h2>User Not Found</h2>";
            echo "<img src='slap.jpg' alt='Not found'>";
        }
    } catch (PDOException $e) {
        echo "<h2>User Not Found</h2>";
        echo "<img src='slap.jpg' alt='Not found'>";
    }
}

function less_time_based($pdo, $id, $quote) {
    // VULNERABLE: Direct concatenation with SLEEP support
    $sql = "SELECT * FROM users WHERE id = $quote$id$quote LIMIT 0,1";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>User Found</h2>";
        } else {
            echo "<h2>User Not Found</h2>";
        }
    } catch (PDOException $e) {
        echo "Error occurred";
    }
}

function show_index() {
    echo "<h1>SQX DB Matrix - MySQL Test Application</h1>";
    echo "<p>Available lessons:</p>";
    echo "<ul>";
    echo "<li><a href='?lesson=Less-1&id=1'>Less-1: Error-based (single quotes)</a></li>";
    echo "<li><a href='?lesson=Less-2&id=1'>Less-2: Error-based (integer)</a></li>";
    echo "<li><a href='?lesson=Less-3&id=1'>Less-3: Error-based (quotes + paren)</a></li>";
    echo "<li><a href='?lesson=Less-4&id=1'>Less-4: Error-based (dbl quotes + paren)</a></li>";
    echo "<li><a href='?lesson=Less-5&id=1'>Less-5: Boolean blind (single quotes)</a></li>";
    echo "<li><a href='?lesson=Less-6&id=1'>Less-6: Boolean blind (double quotes)</a></li>";
    echo "<li><a href='?lesson=Less-8&id=1'>Less-8: Boolean blind (numeric in quotes)</a></li>";
    echo "<li><a href='?lesson=Less-9&id=1'>Less-9: Time-based blind</a></li>";
    echo "<li><a href='?lesson=Less-10&id=1'>Less-10: Time-based blind (dbl quotes)</a></li>";
    echo "</ul>";
}
?>
