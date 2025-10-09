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

// If not logged in, redirect to login
if (!$auth->isLoggedIn()) {
    header('Location: admin_login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Decryption - Admin Area</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/flowbite/1.8.1/flowbite.min.css" rel="stylesheet" />
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <!-- Header with Logout -->
        <div class="flex justify-between items-center mb-8">
            <div class="text-center flex-1">
                <h1 class="text-4xl font-bold text-gray-800 mb-2">🔓 File Decryption</h1>
                <p class="text-gray-600">Admin Area - Secure decryption access</p>
            </div>
            <div>
                <a href="logout.php" class="inline-flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors">
                    <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
                    </svg>
                    Logout
                </a>
            </div>
        </div>

        <!-- Navigation -->
        <div class="text-center mb-8">
            <a href="encrypt.php" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                </svg>
                Go to Encryption Page
            </a>
        </div>

        <!-- Main Content -->
        <div class="max-w-4xl mx-auto">
            <!-- Admin Info Banner -->
            <div class="bg-green-50 border-l-4 border-green-500 p-4 mb-8 rounded">
                <div class="flex items-center">
                    <svg class="h-6 w-6 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <div>
                        <p class="font-medium text-green-800">✅ Admin Authenticated</p>
                        <p class="text-sm text-green-700">You have full access to decryption features</p>
                    </div>
                </div>
            </div>

            <!-- Text Decryption Section -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold text-gray-800 mb-6">📝 Text Decryption</h2>
                
                <div class="grid md:grid-cols-2 gap-6">
                    <!-- Decryption -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-700 mb-3">Decrypt Text</h3>
                        <div class="space-y-4">
                            <div>
                                <label for="textToDecrypt" class="block text-sm font-medium text-gray-700 mb-2">Encrypted Text</label>
                                <textarea id="textToDecrypt" rows="4" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Paste encrypted text here"></textarea>
                            </div>
                            <div>
                                <label for="decryptPassword" class="block text-sm font-medium text-gray-700 mb-2">Password</label>
                                <input type="password" id="decryptPassword" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Enter decryption password">
                            </div>
                            <button onclick="decryptText()" class="w-full bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 transition-colors">
                                🔓 Decrypt Text
                            </button>
                        </div>
                    </div>

                    <!-- Result -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-700 mb-3">Decrypted Result</h3>
                        <div id="textResults" class="hidden">
                            <div class="bg-gray-50 p-4 rounded-md mb-3">
                                <pre id="textResult" class="whitespace-pre-wrap text-sm text-gray-800 max-h-48 overflow-y-auto"></pre>
                            </div>
                            <button onclick="copyTextResult()" class="w-full bg-gray-600 text-white py-2 px-3 rounded hover:bg-gray-700 transition-colors">
                                📋 Copy Result
                            </button>
                        </div>
                        <div id="textResultPlaceholder" class="text-center text-gray-400 py-16">
                            <svg class="mx-auto h-12 w-12 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"></path>
                            </svg>
                            <p>Decrypted text will appear here</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- File Decryption Panel -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold text-gray-800 mb-6">📁 File Decryption</h2>
                
                <div class="max-w-xl mx-auto">
                    <div id="decryptFileDropZone" class="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-gray-400 transition-colors cursor-pointer">
                        <div id="decryptFileContent">
                            <svg class="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                                <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                            </svg>
                            <p class="mt-2 text-sm text-gray-600">Drag and drop encrypted file here</p>
                            <p class="text-xs text-gray-500 mt-1">Select encrypted file (.emilpro)</p>
                        </div>
                        <div id="decryptFilePreview" class="hidden">
                            <div class="flex items-center justify-center mb-4">
                                <svg class="h-8 w-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                            </div>
                            <p id="decryptFileName" class="text-sm font-medium text-gray-900"></p>
                            <p id="decryptFileSize" class="text-xs text-gray-500"></p>
                            <div class="mt-3 flex justify-center space-x-2">
                                <button onclick="document.getElementById('decryptFileInput').click()" class="text-xs text-blue-600 hover:text-blue-500 cursor-pointer">Select New File</button>
                                <span class="text-xs text-gray-400">|</span>
                                <button onclick="clearDecryptFile()" class="text-xs text-red-600 hover:text-red-500 cursor-pointer">Remove</button>
                            </div>
                        </div>
                    </div>
                    <input type="file" id="decryptFileInput" class="hidden" accept=".emilpro" />
                    
                    <div class="mt-4">
                        <label for="decryptFilePassword" class="block text-sm font-medium text-gray-700 mb-2">Password</label>
                        <input type="password" id="decryptFilePassword" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent" placeholder="Enter password for file decryption">
                    </div>
                    
                    <button id="decryptFileBtn" onclick="decryptFile()" disabled class="w-full mt-4 bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed">
                        🔓 Decrypt File
                    </button>
                </div>
            </div>

            <!-- Security Info -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-2xl font-semibold text-gray-800 mb-4">🛡️ Admin Security Info</h2>
                <div class="grid md:grid-cols-2 gap-6">
                    <div>
                        <h3 class="text-lg font-medium text-gray-700 mb-3">Your Access</h3>
                        <ul class="space-y-2 text-sm text-gray-600">
                            <li>✅ <strong>Admin Authenticated:</strong> Full decryption access</li>
                            <li>✅ <strong>Session Secure:</strong> Encrypted session management</li>
                            <li>✅ <strong>Password Locked:</strong> Admin password permanently set</li>
                            <li>✅ <strong>No Database:</strong> File-based secure storage</li>
                            <li>✅ <strong>PBKDF2-SHA512:</strong> 100K iterations password hash</li>
                            <li>✅ <strong>AES-256-CBC:</strong> Config file encryption</li>
                        </ul>
                    </div>
                    <div>
                        <h3 class="text-lg font-medium text-gray-700 mb-3">Important Notes</h3>
                        <ul class="space-y-2 text-sm text-gray-600">
                            <li>🔐 Admin password required for decryption access</li>
                            <li>🔓 Encryption page doesn't require admin login</li>
                            <li>⚠️ Admin password is permanently locked</li>
                            <li>🚪 Logout will end your admin session</li>
                            <li>🔒 Files are protected with read-only permissions</li>
                            <li>💾 Config stored in encrypted files</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast Notification -->
    <div id="toast" class="fixed top-4 right-4 z-50 hidden">
        <div class="bg-white border-l-4 p-4 shadow-lg rounded-md max-w-sm">
            <div class="flex">
                <div class="flex-shrink-0">
                    <span id="toastIcon" class="text-2xl"></span>
                </div>
                <div class="ml-3">
                    <p id="toastMessage" class="text-sm font-medium text-gray-800"></p>
                </div>
                <div class="ml-auto pl-3">
                    <button onclick="hideNotification()" class="text-gray-400 hover:text-gray-600">
                        <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                        </svg>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Loading Overlay -->
    <div id="loadingOverlay" class="fixed inset-0 bg-black bg-opacity-50 z-50 hidden">
        <div class="flex items-center justify-center min-h-screen">
            <div class="bg-white p-6 rounded-lg shadow-lg">
                <div class="flex items-center">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-green-600"></div>
                    <span class="ml-3 text-gray-700" id="loadingText">Processing...</span>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/flowbite/1.8.1/flowbite.min.js"></script>
    <script>
        let selectedDecryptFile = null;

        document.addEventListener('DOMContentLoaded', function() {
            setupFileDropZone();
        });

        function setupFileDropZone() {
            const decryptDropZone = document.getElementById('decryptFileDropZone');
            const decryptFileInput = document.getElementById('decryptFileInput');

            decryptDropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                decryptDropZone.classList.add('border-green-400', 'bg-green-50');
            });

            decryptDropZone.addEventListener('dragleave', (e) => {
                e.preventDefault();
                decryptDropZone.classList.remove('border-green-400', 'bg-green-50');
            });

            decryptDropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                decryptDropZone.classList.remove('border-green-400', 'bg-green-50');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    handleDecryptFile(files[0]);
                }
            });

            decryptFileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    handleDecryptFile(e.target.files[0]);
                }
            });
        }

        function handleDecryptFile(file) {
            selectedDecryptFile = file;
            document.getElementById('decryptFileName').textContent = file.name;
            document.getElementById('decryptFileSize').textContent = formatFileSize(file.size);
            document.getElementById('decryptFileContent').classList.add('hidden');
            document.getElementById('decryptFilePreview').classList.remove('hidden');
            document.getElementById('decryptFileBtn').disabled = false;
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function clearDecryptFile() {
            selectedDecryptFile = null;
            document.getElementById('decryptFileInput').value = '';
            document.getElementById('decryptFileContent').classList.remove('hidden');
            document.getElementById('decryptFilePreview').classList.add('hidden');
            document.getElementById('decryptFileBtn').disabled = true;
            document.getElementById('decryptFilePassword').value = '';
        }

        async function decryptText() {
            const text = document.getElementById('textToDecrypt').value;
            const password = document.getElementById('decryptPassword').value;

            if (!text || !password) {
                showNotification('Please enter both encrypted text and password', 'error');
                return;
            }

            showLoading('Decrypting text...');

            try {
                const response = await fetch('api.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        action: 'decrypt',
                        text: text,
                        password: password
                    })
                });

                const data = await response.json();
                hideLoading();

                if (data.success) {
                    document.getElementById('textResult').textContent = data.decrypted;
                    document.getElementById('textResults').classList.remove('hidden');
                    document.getElementById('textResultPlaceholder').classList.add('hidden');
                    showNotification('Text decrypted successfully!', 'success');
                } else {
                    showNotification('Decryption failed: ' + data.error, 'error');
                }
            } catch (error) {
                hideLoading();
                showNotification('Decryption failed: ' + error.message, 'error');
            }
        }

        async function decryptFile() {
            if (!selectedDecryptFile) {
                showNotification('Please select a file first', 'error');
                return;
            }

            const password = document.getElementById('decryptFilePassword').value;
            if (!password) {
                showNotification('Please enter a password', 'error');
                return;
            }

            showLoading('Decrypting file...');

            const formData = new FormData();
            formData.append('action', 'decrypt_file');
            formData.append('file', selectedDecryptFile);
            formData.append('password', password);

            try {
                const response = await fetch('api.php', {
                    method: 'POST',
                    body: formData
                });

                if (response.ok) {
                    const contentType = response.headers.get('content-type');
                    
                    if (contentType && contentType.includes('application/json')) {
                        const errorData = await response.json();
                        showNotification('Decryption failed: ' + errorData.error, 'error');
                    } else {
                        const blob = await response.blob();
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.style.display = 'none';
                        a.href = url;
                        
                        const contentDisposition = response.headers.get('content-disposition');
                        let filename = 'decrypted_file';
                        if (contentDisposition) {
                            const filenameMatch = contentDisposition.match(/filename="(.+)"/);
                            if (filenameMatch) {
                                filename = filenameMatch[1];
                            }
                        }
                        
                        a.download = filename;
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);
                        
                        showNotification('File decrypted successfully!', 'success');
                    }
                } else {
                    const errorData = await response.json();
                    showNotification('Decryption failed: ' + errorData.error, 'error');
                }
                
                hideLoading();
            } catch (error) {
                hideLoading();
                showNotification('Decryption failed: ' + error.message, 'error');
            }
        }

        function copyTextResult() {
            const result = document.getElementById('textResult');
            navigator.clipboard.writeText(result.textContent).then(() => {
                showNotification('Result copied to clipboard!', 'success');
            }).catch(() => {
                showNotification('Failed to copy to clipboard', 'error');
            });
        }

        function showNotification(message, type = 'info') {
            const toast = document.getElementById('toast');
            const toastIcon = document.getElementById('toastIcon');
            const toastMessage = document.getElementById('toastMessage');

            toastIcon.textContent = type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️';
            toastMessage.textContent = message;

            const borderColor = type === 'success' ? 'border-green-400' : type === 'error' ? 'border-red-400' : 'border-blue-400';
            toast.firstElementChild.className = `bg-white ${borderColor} border-l-4 p-4 shadow-lg rounded-md max-w-sm`;

            toast.classList.remove('hidden');

            setTimeout(() => {
                hideNotification();
            }, 5000);
        }

        function hideNotification() {
            document.getElementById('toast').classList.add('hidden');
        }

        function showLoading(text = 'Processing...') {
            document.getElementById('loadingText').textContent = text;
            document.getElementById('loadingOverlay').classList.remove('hidden');
        }

        function hideLoading() {
            document.getElementById('loadingOverlay').classList.add('hidden');
        }
    </script>
</body>
</html>

