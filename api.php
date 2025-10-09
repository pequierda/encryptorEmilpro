<?php

// Suppress all error output to prevent HTML errors from breaking JSON
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Clean any previous output
ob_clean();

try {
    // Check if encryption.php exists and include it
    $encryptionFile = __DIR__ . '/encryption.php';
    if (!file_exists($encryptionFile)) {
        throw new Exception('Encryption file not found: ' . $encryptionFile);
    }
    
    require_once $encryptionFile;
    
    // Check if class exists
    if (!class_exists('AdvancedEncryptor')) {
        throw new Exception('AdvancedEncryptor class not found in encryption.php');
    }
    
    // Handle different request types
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
        // File upload request
        $action = $_POST['action'] ?? '';
    } else {
        // JSON request
        $input = json_decode(file_get_contents('php://input'), true);
        if (!$input || !isset($input['action'])) {
            throw new Exception('Invalid request');
        }
        $action = $input['action'];
    }
    
    $encryptor = new AdvancedEncryptor();
    
    switch ($action) {
        case 'encrypt':
            if (!isset($input['text']) || !isset($input['password'])) {
                throw new Exception('Missing required parameters');
            }
            
            $text = $input['text'];
            $password = $input['password'];
            
            if (empty($text) || empty($password)) {
                throw new Exception('Text and password cannot be empty');
            }
            
            $encryptedData = $encryptor->encryptWithoutRSA($text, $password);
            
            echo json_encode([
                'success' => true,
                'encrypted_data' => $encryptedData,
                'algorithm' => 'aes-256-gcm-pbkdf2-triple-xor-enhanced'
            ]);
            break;
            
        case 'decrypt':
            if (!isset($input['text']) || !isset($input['password'])) {
                throw new Exception('Missing required parameters');
            }
            
            $encryptedData = $input['text'];
            $password = $input['password'];
            
            if (empty($encryptedData) || empty($password)) {
                throw new Exception('Encrypted data and password cannot be empty');
            }
            
            $decryptedData = $encryptor->decryptWithoutRSA($encryptedData, $password);
            
            echo json_encode([
                'success' => true,
                'decrypted' => $decryptedData
            ]);
            break;
            
            
        case 'info':
            echo json_encode([
                'success' => true,
                'info' => $encryptor->getEncryptionInfo()
            ]);
            break;
            
        case 'test':
            echo json_encode([
                'success' => true,
                'message' => 'API is working correctly',
                'timestamp' => date('Y-m-d H:i:s'),
                'encryption_file_exists' => file_exists($encryptionFile),
                'encryption_file_path' => $encryptionFile,
                'class_exists' => class_exists('AdvancedEncryptor'),
                'current_dir' => __DIR__
            ]);
            break;
            
        case 'encrypt_file':
            if (!isset($_FILES['file']) || !isset($_POST['password'])) {
                throw new Exception('Missing file or password');
            }
            
            $file = $_FILES['file'];
            $password = $_POST['password'];
            
            if ($file['error'] !== UPLOAD_ERR_OK) {
                throw new Exception('File upload error: ' . $file['error']);
            }
            
            if (empty($password)) {
                throw new Exception('Password cannot be empty');
            }
            
            $fileContent = file_get_contents($file['tmp_name']);
            $filename = $file['name'];
            
            $encryptedData = $encryptor->encryptFile($fileContent, $filename, $password);
            
            // Set headers for file download
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . $filename . '.emilpro"');
            header('Content-Length: ' . strlen($encryptedData));
            
            echo $encryptedData;
            exit;
            
        case 'decrypt_file':
            if (!isset($_FILES['file']) || !isset($_POST['password'])) {
                throw new Exception('Missing file or password');
            }
            
            $file = $_FILES['file'];
            $password = $_POST['password'];
            
            if ($file['error'] !== UPLOAD_ERR_OK) {
                throw new Exception('File upload error: ' . $file['error']);
            }
            
            if (empty($password)) {
                throw new Exception('Password cannot be empty');
            }
            
            $encryptedData = file_get_contents($file['tmp_name']);
            
            
            $decryptedFile = $encryptor->decryptFile($encryptedData, $password);
            
            // Set headers for file download
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . $decryptedFile['filename'] . '"');
            header('Content-Length: ' . strlen($decryptedFile['content']));
            
            echo $decryptedFile['content'];
            exit;
            
        default:
            throw new Exception('Invalid action');
    }
    
} catch (Exception $e) {
    // Clean any output buffer before sending error
    ob_clean();
    
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
    
    // Log the error for debugging
    error_log('API Error: ' . $e->getMessage());
} catch (Error $e) {
    // Clean any output buffer before sending error
    ob_clean();
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Internal server error: ' . $e->getMessage()
    ]);
    
    // Log the error for debugging
    error_log('API Fatal Error: ' . $e->getMessage());
}

?>
