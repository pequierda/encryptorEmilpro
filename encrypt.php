<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Encryption - No Login Required</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/flowbite/1.8.1/flowbite.min.css" rel="stylesheet" />
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <!-- Header -->
        <div class="text-center mb-8">
            <h1 class="text-4xl font-bold text-gray-800 mb-2">🔐 File Encryption</h1>
            <p class="text-gray-600">Secure your files with military-grade encryption</p>
            <div class="mt-4">
                <a href="admin_login.php" class="inline-flex items-center px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors">
                    <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"></path>
                    </svg>
                    Go to Decryption (Admin Required)
                </a>
            </div>
        </div>

        <!-- Main Content -->
        <div class="max-w-4xl mx-auto">
            <!-- Text Encryption Section -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold text-gray-800 mb-6">📝 Text Encryption</h2>
                
                <div class="grid md:grid-cols-2 gap-6">
                    <!-- Encryption -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-700 mb-3">Encrypt Text</h3>
                        <div class="space-y-4">
                            <div>
                                <label for="textToEncrypt" class="block text-sm font-medium text-gray-700 mb-2">Text to Encrypt</label>
                                <textarea id="textToEncrypt" rows="4" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="Enter text to encrypt"></textarea>
                            </div>
                            <div>
                                <label for="encryptPassword" class="block text-sm font-medium text-gray-700 mb-2">Password</label>
                                <input type="password" id="encryptPassword" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="Enter encryption password">
                            </div>
                            <button onclick="encryptText()" class="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors">
                                🔒 Encrypt Text
                            </button>
                        </div>
                    </div>

                    <!-- Result -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-700 mb-3">Encrypted Result</h3>
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
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                            </svg>
                            <p>Encrypted text will appear here</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- File Upload Panel -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold text-gray-800 mb-6">📁 File Encryption</h2>
                
                <div class="max-w-xl mx-auto">
                    <div id="encryptFileDropZone" class="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-gray-400 transition-colors cursor-pointer">
                        <div id="encryptFileContent">
                            <svg class="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                                <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                            </svg>
                            <p class="mt-2 text-sm text-gray-600">Drag and drop a file here</p>
                            <p class="text-xs text-gray-500 mt-1">Supports any file type</p>
                        </div>
                        <div id="encryptFilePreview" class="hidden">
                            <div class="flex items-center justify-center mb-4">
                                <svg class="h-8 w-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                            </div>
                            <p id="encryptFileName" class="text-sm font-medium text-gray-900"></p>
                            <p id="encryptFileSize" class="text-xs text-gray-500"></p>
                            <div class="mt-3 flex justify-center space-x-2">
                                <button onclick="document.getElementById('encryptFileInput').click()" class="text-xs text-blue-600 hover:text-blue-500 cursor-pointer">Select New File</button>
                                <span class="text-xs text-gray-400">|</span>
                                <button onclick="clearEncryptFile()" class="text-xs text-red-600 hover:text-red-500 cursor-pointer">Remove</button>
                            </div>
                        </div>
                    </div>
                    <input type="file" id="encryptFileInput" class="hidden" />
                    
                    <div class="mt-4">
                        <label for="encryptFilePassword" class="block text-sm font-medium text-gray-700 mb-2">Password</label>
                        <input type="password" id="encryptFilePassword" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="Enter password for file encryption">
                    </div>
                    
                    <button id="encryptFileBtn" onclick="encryptFile()" disabled class="w-full mt-4 bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed">
                        🔒 Encrypt File
                    </button>
                </div>
            </div>

            <!-- Encryption Info -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-2xl font-semibold text-gray-800 mb-4">🛡️ Encryption Details</h2>
                <div class="grid md:grid-cols-2 gap-6">
                    <div>
                        <h3 class="text-lg font-medium text-gray-700 mb-3">Security Features</h3>
                        <ul class="space-y-2 text-sm text-gray-600">
                            <li>✅ <strong>AES-256-GCM:</strong> Military-grade symmetric encryption</li>
                            <li>✅ <strong>PBKDF2-SHA512:</strong> Password-based key derivation</li>
                            <li>✅ <strong>XOR Obfuscation:</strong> Additional data scrambling</li>
                            <li>✅ <strong>Base64 + Hex:</strong> Multi-layer encoding</li>
                            <li>✅ <strong>Secure Random:</strong> Cryptographically secure salts</li>
                            <li>✅ <strong>File Format:</strong> Preserves original file types</li>
                        </ul>
                    </div>
                    <div>
                        <h3 class="text-lg font-medium text-gray-700 mb-3">Access Control</h3>
                        <ul class="space-y-2 text-sm text-gray-600">
                            <li>🔓 <strong>Encryption:</strong> No admin password required</li>
                            <li>🔐 <strong>Decryption:</strong> Requires admin login</li>
                            <li>⚠️ <strong>First Setup:</strong> Admin password must be set once</li>
                            <li>🔒 <strong>Permanent Lock:</strong> Password cannot be changed after setup</li>
                            <li>🛡️ <strong>Session Security:</strong> Secure admin sessions</li>
                            <li>📁 <strong>No Database:</strong> File-based storage only</li>
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
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                    <span class="ml-3 text-gray-700" id="loadingText">Processing...</span>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/flowbite/1.8.1/flowbite.min.js"></script>
    <script>
        let selectedEncryptFile = null;

        document.addEventListener('DOMContentLoaded', function() {
            setupFileDropZone();
        });

        function setupFileDropZone() {
            const encryptDropZone = document.getElementById('encryptFileDropZone');
            const encryptFileInput = document.getElementById('encryptFileInput');

            encryptDropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                encryptDropZone.classList.add('border-blue-400', 'bg-blue-50');
            });

            encryptDropZone.addEventListener('dragleave', (e) => {
                e.preventDefault();
                encryptDropZone.classList.remove('border-blue-400', 'bg-blue-50');
            });

            encryptDropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                encryptDropZone.classList.remove('border-blue-400', 'bg-blue-50');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    handleEncryptFile(files[0]);
                }
            });

            encryptFileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    handleEncryptFile(e.target.files[0]);
                }
            });
        }

        function handleEncryptFile(file) {
            selectedEncryptFile = file;
            document.getElementById('encryptFileName').textContent = file.name;
            document.getElementById('encryptFileSize').textContent = formatFileSize(file.size);
            document.getElementById('encryptFileContent').classList.add('hidden');
            document.getElementById('encryptFilePreview').classList.remove('hidden');
            document.getElementById('encryptFileBtn').disabled = false;
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function clearEncryptFile() {
            selectedEncryptFile = null;
            document.getElementById('encryptFileInput').value = '';
            document.getElementById('encryptFileContent').classList.remove('hidden');
            document.getElementById('encryptFilePreview').classList.add('hidden');
            document.getElementById('encryptFileBtn').disabled = true;
            document.getElementById('encryptFilePassword').value = '';
        }

        async function encryptText() {
            const text = document.getElementById('textToEncrypt').value;
            const password = document.getElementById('encryptPassword').value;

            if (!text || !password) {
                showNotification('Please enter both text and password', 'error');
                return;
            }

            showLoading('Encrypting text...');

            try {
                const response = await fetch('api.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        action: 'encrypt',
                        text: text,
                        password: password
                    })
                });

                const data = await response.json();
                hideLoading();

                if (data.success) {
                    document.getElementById('textResult').textContent = data.encrypted_data;
                    document.getElementById('textResults').classList.remove('hidden');
                    document.getElementById('textResultPlaceholder').classList.add('hidden');
                    showNotification('Text encrypted successfully!', 'success');
                } else {
                    showNotification('Encryption failed: ' + data.error, 'error');
                }
            } catch (error) {
                hideLoading();
                showNotification('Encryption failed: ' + error.message, 'error');
            }
        }

        async function encryptFile() {
            if (!selectedEncryptFile) {
                showNotification('Please select a file first', 'error');
                return;
            }

            const password = document.getElementById('encryptFilePassword').value;
            if (!password) {
                showNotification('Please enter a password', 'error');
                return;
            }

            showLoading('Encrypting file...');

            const formData = new FormData();
            formData.append('action', 'encrypt_file');
            formData.append('file', selectedEncryptFile);
            formData.append('password', password);

            try {
                const response = await fetch('api.php', {
                    method: 'POST',
                    body: formData
                });

                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = selectedEncryptFile.name + '.emilpro';
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                    
                    showNotification('File encrypted successfully!', 'success');
                    hideLoading();
                } else {
                    const errorData = await response.json();
                    showNotification('Encryption failed: ' + errorData.error, 'error');
                    hideLoading();
                }
            } catch (error) {
                hideLoading();
                showNotification('Encryption failed: ' + error.message, 'error');
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

