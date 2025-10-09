<?php
// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'admin_auth.php';

$auth = new AdminAuth();
$auth->logout();

// Add security headers to prevent caching of logout page
header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

// Redirect to encryption page
header('Location: encrypt.php');
exit;
?>

