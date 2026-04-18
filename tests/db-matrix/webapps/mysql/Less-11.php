<?php
/**
 * POST-based SQL injection (Less-11 equivalent)
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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $uname = $_POST['uname'] ?? '';
    $passwd = $_POST['passwd'] ?? '';
    
    // VULNERABLE: Direct concatenation in POST handler
    $sql = "SELECT * FROM users WHERE username = '$uname' AND password = '$passwd' LIMIT 0,1";
    
    try {
        $stmt = $pdo->query($sql);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row) {
            echo "<h2>Login Successful</h2>";
            echo "Welcome, " . htmlspecialchars($row['username']) . "!<br>";
            echo "Your password: " . htmlspecialchars($row['password']) . "<br>";
        } else {
            echo "<h2>Login Failed</h2>";
        }
    } catch (PDOException $e) {
        echo "SQL Error: " . $e->getMessage();
    }
} else {
    // Show login form
    ?>
    <h2>Login Form (Less-11)</h2>
    <form method="POST">
        Username: <input type="text" name="uname"><br>
        Password: <input type="password" name="passwd"><br>
        <input type="submit" value="Submit">
    </form>
    <?php
}
?>
