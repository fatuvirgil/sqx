<?php
// php-safe/index.php - Endpoints that use SAFE practices
// SQX should report: 0% confidence, NO VULNERABILITIES

header('Content-Type: application/json');

// DB Connection
$host = getenv('MYSQL_HOST') ?: 'localhost';
$db = getenv('MYSQL_DB') ?: 'testdb';
$user = getenv('MYSQL_USER') ?: 'testuser';
$pass = getenv('MYSQL_PASS') ?: 'testpass';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
} catch (PDOException $e) {
    die(json_encode(['error' => 'DB connection failed']));
}

$route = $_GET['route'] ?? '';

switch ($route) {
    // ============================================
    // TEST 1: PDO Prepared Statements (TRUE SAFE)
    // ============================================
    case 'pdo-prepared':
        $id = $_GET['id'] ?? '1';
        // ABSOLUTELY SAFE - Parameterized query
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['safe' => true, 'method' => 'PDO prepared', 'results' => count($result)]);
        break;

    // ============================================
    // TEST 2: PDO Named Parameters (TRUE SAFE)
    // ============================================
    case 'pdo-named':
        $id = $_GET['id'] ?? '1';
        $name = $_GET['name'] ?? 'test';
        // SAFE - Named placeholders
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id AND name = :name");
        $stmt->execute([':id' => $id, ':name' => $name]);
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['safe' => true, 'method' => 'PDO named params', 'results' => count($result)]);
        break;

    // ============================================
    // TEST 3: Input Validation + Prepared (DEFENSE IN DEPTH)
    // ============================================
    case 'validated-prepared':
        $id = $_GET['id'] ?? '1';
        // Validation: must be integer
        if (!filter_var($id, FILTER_VALIDATE_INT)) {
            echo json_encode(['error' => 'Invalid input', 'safe' => true]);
            break;
        }
        // Then prepared statement
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['safe' => true, 'method' => 'validated + prepared', 'results' => count($result)]);
        break;

    // ============================================
    // TEST 4: LIKE Query with Prepared (TRICKY - often FP)
    // ============================================
    case 'like-prepared':
        $search = $_GET['search'] ?? 'test';
        // SAFE - Even with LIKE wildcards, prepared handles it
        $stmt = $pdo->prepare("SELECT * FROM users WHERE name LIKE ?");
        $stmt->execute(["%$search%"]); // Bound as parameter, not concatenated
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['safe' => true, 'method' => 'LIKE prepared', 'results' => count($result)]);
        break;

    // ============================================
    // TEST 5: IN Clause with Prepared (ARRAY - SAFE)
    // ============================================
    case 'in-prepared':
        $ids = $_GET['ids'] ?? '1,2,3';
        $idArray = explode(',', $ids);
        // SAFE - Dynamic placeholders but parameterized
        $placeholders = implode(',', array_fill(0, count($idArray), '?'));
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id IN ($placeholders)");
        $stmt->execute($idArray);
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['safe' => true, 'method' => 'IN clause prepared', 'results' => count($result)]);
        break;

    // ============================================
    // TEST 6: Stored Procedure with Parameters (SAFE)
    // ============================================
    case 'stored-proc':
        $id = $_GET['id'] ?? '1';
        // SAFE - Stored procedure with bound parameter
        $stmt = $pdo->prepare("CALL get_user_by_id(?)");
        $stmt->execute([$id]);
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['safe' => true, 'method' => 'stored procedure', 'results' => count($result)]);
        break;

    // ============================================
    // TEST 7: ORM-style Query Builder (SAFE)
    // ============================================
    case 'orm-style':
        $id = $_GET['id'] ?? '1';
        $name = $_GET['name'] ?? '';
        // Simulating ORM - safe array building
        $where = [];
        $params = [];
        
        if (is_numeric($id)) {
            $where[] = "id = ?";
            $params[] = $id;
        }
        if (!empty($name)) {
            $where[] = "name = ?";
            $params[] = $name;
        }
        
        if (empty($where)) {
            echo json_encode(['safe' => true, 'results' => 0]);
            break;
        }
        
        $sql = "SELECT * FROM users WHERE " . implode(' AND ', $where);
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['safe' => true, 'method' => 'ORM-style builder', 'results' => count($result)]);
        break;

    // ============================================
    // TEST 8: Escaped but NOT prepared (LEGACY - RISKY but not vulnerable to classic SQLi)
    // ============================================
    case 'escaped-legacy':
        $id = $_GET['id'] ?? '1';
        // RISKY but technically safe for basic SQLi (mysql_real_escape_string handles quotes)
        // Note: Still not recommended, but should not trigger Boolean/Error detection
        $escaped = $pdo->quote($id); // quote() adds quotes and escapes
        $stmt = $pdo->query("SELECT * FROM users WHERE id = $escaped");
        $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['safe' => true, 'method' => 'legacy escaped (discouraged)', 'results' => count($result)]);
        break;

    // ============================================
    // TEST 9: Non-SQL parameter (Cache key)
    // ============================================
    case 'cache-key':
        $key = $_GET['key'] ?? 'user_1';
        // NOT SQL - just a cache lookup
        $mockCache = ['user_1' => 'data', 'user_2' => 'data'];
        $result = $mockCache[$key] ?? null;
        echo json_encode(['safe' => true, 'method' => 'cache lookup (no SQL)', 'hit' => $result !== null]);
        break;

    // ============================================
    // TEST 10: Logging endpoint (no SQL)
    // ============================================
    case 'logging':
        $action = $_GET['action'] ?? 'view';
        $userId = $_GET['user_id'] ?? '1';
        // Just logging, no database query
        $log = "User $userId performed $action at " . date('Y-m-d H:i:s');
        file_put_contents('/tmp/app.log', $log . "\n", FILE_APPEND);
        echo json_encode(['safe' => true, 'method' => 'file logging (no SQL)', 'logged' => true]);
        break;

    default:
        echo json_encode([
            'service' => 'PHP False Positive Test Suite',
            'endpoints' => [
                'pdo-prepared' => 'True parameterized query',
                'pdo-named' => 'Named placeholders',
                'validated-prepared' => 'Input validation + prepared',
                'like-prepared' => 'LIKE with wildcards (prepared)',
                'in-prepared' => 'IN clause with array (prepared)',
                'stored-proc' => 'Stored procedure with params',
                'orm-style' => 'ORM-style query builder',
                'escaped-legacy' => 'Legacy escaped (discouraged)',
                'cache-key' => 'Non-SQL cache lookup',
                'logging' => 'Non-SQL file logging'
            ]
        ]);
}
