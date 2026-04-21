<?php
// proxy.php - Auto-refreshes expired tokens using PHP session

session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit(); }

if (!isset($_SESSION['guard_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Session expired. Please log out and login again.']);
    exit;
}

require_once __DIR__ . '/db.php';

$guardId      = $_SESSION['guard_id'];
$sessionToken = $_SESSION['token'] ?? '';

// Check if token is valid, refresh if expired
$db  = getDB();
$chk = $db->prepare("SELECT id FROM guard_sessions WHERE token = ? AND expires_at > NOW()");
$chk->bind_param('s', $sessionToken);
$chk->execute();
$valid = $chk->get_result()->num_rows > 0;
$chk->close();

if (!$valid) {
    // Auto-refresh token
    $newToken  = bin2hex(random_bytes(32));
    $newExpiry = date('Y-m-d H:i:s', strtotime('+24 hours'));
    $db->prepare("DELETE FROM guard_sessions WHERE guard_id = ?")->execute([$guardId]);
    $ins = $db->prepare("INSERT INTO guard_sessions (guard_id, token, expires_at) VALUES (?, ?, ?)");
    $ins->bind_param('iss', $guardId, $newToken, $newExpiry);
    $ins->execute();
    $ins->close();
    $_SESSION['token'] = $newToken;
    $sessionToken      = $newToken;
}
$db->close();

// Allowed endpoints
$allowed = ['vehicle-intake','vehicle-exit','vehicle-entries','dashboard',
            'employees','export-excel','cancel-entry','parking-slots',
            'employee-parking','create-guard','list-guards',
            'reset-guard-password','deactivate-guard','change-password','daily-report'];

$endpoint = trim($_GET['endpoint'] ?? '');
if (!in_array($endpoint, $allowed)) {
    http_response_code(404);
    echo json_encode(['success' => false, 'message' => 'Endpoint not found.']);
    exit;
}

// Build target URL
$params = $_GET;
unset($params['endpoint']);
$targetUrl = 'http://localhost/fumc_parking/' . $endpoint;
if (!empty($params)) $targetUrl .= '?' . http_build_query($params);

// Forward request
$method  = $_SERVER['REQUEST_METHOD'];
$body    = file_get_contents('php://input');

$ctx = stream_context_create(['http' => [
    'method'         => $method,
    'header'         => "Content-Type: application/json\r\nAuthorization: Bearer $sessionToken\r\n",
    'content'        => $body,
    'ignore_errors'  => true,
    'timeout'        => 30,
]]);

$response = @file_get_contents($targetUrl, false, $ctx);

if ($response === false) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Could not reach API server.']);
    exit;
}

echo $response;
