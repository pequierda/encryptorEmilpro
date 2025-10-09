<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once 'admin_auth.php';

$auth = new AdminAuth();

// If password not set, redirect to setup
if (!$auth->isPasswordSet()) {
    header('Location: setup.php');
    exit;
}

// If already logged in, redirect to decrypt page
if ($auth->isLoggedIn()) {
    header('Location: decrypt.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $password = $_POST['password'] ?? '';
    
    if (empty($password)) {
        $error = 'Password is required';
    } else {
        if ($auth->login($password)) {
            header('Location: decrypt.php');
            exit;
        } else {
            $error = 'Invalid admin password';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Decryption Access</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-indigo-50 to-purple-100 min-h-screen">
    <div class="container mx-auto px-4 py-16">
        <div class="max-w-md mx-auto">
            <!-- Login Card -->
            <div class="bg-white rounded-xl shadow-2xl p-8">
                <div class="text-center mb-8">
                    <div class="inline-flex items-center justify-center w-16 h-16 bg-indigo-100 rounded-full mb-4">
                        <svg class="h-8 w-8 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                        </svg>
                    </div>
                    <h1 class="text-3xl font-bold text-gray-800 mb-2">Admin Login</h1>
                    <p class="text-gray-600">Enter your admin password to access decryption</p>
                </div>

                <?php if ($error): ?>
                    <div class="bg-red-50 border-l-4 border-red-500 p-4 mb-6 rounded">
                        <div class="flex items-center">
                            <svg class="h-6 w-6 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            <p class="text-red-700 font-medium"><?= htmlspecialchars($error) ?></p>
                        </div>
                    </div>
                <?php endif; ?>

                <form method="POST" action="" class="space-y-6">
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
                            Admin Password
                        </label>
                        <input type="password" id="password" name="password" required autofocus
                               class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                               placeholder="Enter your admin password">
                    </div>

                    <button type="submit" name="login"
                            class="w-full bg-indigo-600 text-white py-3 px-4 rounded-lg font-semibold hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition-colors">
                        🔓 Login to Decrypt
                    </button>
                </form>

                <div class="mt-6 text-center">
                    <a href="encrypt.php" class="text-sm text-indigo-600 hover:text-indigo-800">
                        ← Back to Encryption (No login required)
                    </a>
                </div>
            </div>

            <!-- Info Box -->
            <div class="mt-6 bg-white rounded-lg shadow p-4">
                <h3 class="font-semibold text-gray-800 mb-2">🔐 Security Info:</h3>
                <ul class="text-sm text-gray-600 space-y-1">
                    <li>✓ Admin password protects decryption access</li>
                    <li>✓ Password is permanently locked after first setup</li>
                    <li>✓ Encryption doesn't require admin password</li>
                    <li>✓ Your session is secure and encrypted</li>
                </ul>
            </div>

        </div>
    </div>
</body>
</html>

