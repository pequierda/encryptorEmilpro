<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once 'admin_auth.php';

$auth = new AdminAuth();

// If already locked, redirect to login
if ($auth->isLocked()) {
    header('Location: admin_login.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['setup_password'])) {
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    
    if (empty($password)) {
        $error = 'Password is required';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters long';
    } elseif ($password !== $confirmPassword) {
        $error = 'Passwords do not match';
    } else {
        try {
            $auth->setPassword($password);
            $success = 'Admin password set successfully! This password is now PERMANENTLY LOCKED and cannot be changed.';
            // Auto-login after setup
            $auth->login($password);
            // Redirect to decrypt page after 3 seconds
            header('refresh:3;url=decrypt.php');
        } catch (Exception $e) {
            $error = $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Setup - First Time Setup</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen">
    <div class="container mx-auto px-4 py-16">
        <div class="max-w-md mx-auto">
            <!-- Warning Banner -->
            <div class="bg-red-600 text-white p-4 rounded-lg mb-6 shadow-lg">
                <div class="flex items-center">
                    <svg class="h-6 w-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                    </svg>
                    <div>
                        <p class="font-bold">⚠️ CRITICAL WARNING!</p>
                        <p class="text-sm">This password will be PERMANENTLY LOCKED after setup!</p>
                    </div>
                </div>
            </div>

            <!-- Setup Card -->
            <div class="bg-white rounded-xl shadow-2xl p-8">
                <div class="text-center mb-6">
                    <div class="inline-flex items-center justify-center w-16 h-16 bg-indigo-100 rounded-full mb-4">
                        <svg class="h-8 w-8 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                        </svg>
                    </div>
                    <h1 class="text-3xl font-bold text-gray-800 mb-2">First Time Setup</h1>
                    <p class="text-gray-600">Set your admin password for decryption access</p>
                </div>

                <?php if ($success): ?>
                    <div class="bg-green-50 border-l-4 border-green-500 p-4 mb-6 rounded">
                        <div class="flex items-center">
                            <svg class="h-6 w-6 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            <p class="text-green-700 font-medium"><?= htmlspecialchars($success) ?></p>
                        </div>
                        <p class="text-green-600 text-sm mt-2">Redirecting to decrypt page...</p>
                    </div>
                <?php elseif ($error): ?>
                    <div class="bg-red-50 border-l-4 border-red-500 p-4 mb-6 rounded">
                        <div class="flex items-center">
                            <svg class="h-6 w-6 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            <p class="text-red-700 font-medium"><?= htmlspecialchars($error) ?></p>
                        </div>
                    </div>
                <?php endif; ?>

                <?php if (!$success): ?>
                    <!-- Important Notice -->
                    <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
                        <h3 class="font-semibold text-yellow-800 mb-2">🔒 Important Notice:</h3>
                        <ul class="text-sm text-yellow-700 space-y-1">
                            <li>✓ This password protects your decryption access</li>
                            <li>✓ Once set, it <strong>CANNOT be changed</strong></li>
                            <li>✓ Keep it safe and memorable</li>
                            <li>✓ If lost, you'll need to delete config files manually</li>
                        </ul>
                    </div>

                    <form method="POST" action="" class="space-y-6">
                        <div>
                            <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
                                Admin Password
                            </label>
                            <input type="password" id="password" name="password" required
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                                   placeholder="Enter admin password (min 8 characters)"
                                   minlength="8">
                            <p class="text-xs text-gray-500 mt-1">Minimum 8 characters. Use strong password!</p>
                        </div>

                        <div>
                            <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-2">
                                Confirm Password
                            </label>
                            <input type="password" id="confirm_password" name="confirm_password" required
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                                   placeholder="Confirm admin password"
                                   minlength="8">
                        </div>

                        <button type="submit" name="setup_password"
                                class="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg font-semibold hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-colors">
                            🔐 Set Admin Password (Permanent)
                        </button>
                    </form>

                    <div class="mt-6 text-center">
                        <a href="encrypt.php" class="text-sm text-indigo-600 hover:text-indigo-800">
                            ← Back to Encryption (No password required)
                        </a>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Security Info -->
            <div class="mt-6 bg-white rounded-lg shadow p-4">
                <h3 class="font-semibold text-gray-800 mb-2">🛡️ Security Features:</h3>
                <ul class="text-sm text-gray-600 space-y-1">
                    <li>✓ Password hashed with PBKDF2-SHA512 (100K iterations)</li>
                    <li>✓ Configuration encrypted with AES-256-CBC</li>
                    <li>✓ Files locked as read-only after setup</li>
                    <li>✓ No database - secure file storage only</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>

