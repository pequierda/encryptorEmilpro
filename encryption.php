<?php

// Suppress warnings that might interfere with JSON output
error_reporting(E_ERROR | E_PARSE);

class AdvancedEncryptor {
    private $aesKeyLength = 32; // 256 bits
    private $rsaKeySize = 4096;
    private $pbkdf2Iterations = 100000;
    private $saltLength = 32;
    
    public function __construct() {
        if (!extension_loaded('openssl')) {
            throw new Exception('OpenSSL extension is required');
        }
    }
    
    /**
     * Generate cryptographically secure random bytes
     */
    private function generateSecureRandom($length) {
        if (function_exists('random_bytes')) {
            return random_bytes($length);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes($length, $strong);
            if (!$strong) {
                throw new Exception('Unable to generate secure random bytes');
            }
            return $bytes;
        } else {
            throw new Exception('No secure random number generator available');
        }
    }
    
    /**
     * Generate PBKDF2 key from password
     */
    private function deriveKey($password, $salt, $iterations = null) {
        $iterations = $iterations ?? $this->pbkdf2Iterations;
        return hash_pbkdf2('sha512', $password, $salt, $iterations, $this->aesKeyLength, true);
    }
    
    /**
     * Generate RSA key pair with proper OpenSSL configuration
     */
    public function generateRSAKeyPair() {
        // Create OpenSSL configuration for Windows/XAMPP compatibility
        $config = [
            "digest_alg" => "sha512",
            "private_key_bits" => $this->rsaKeySize,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "encrypt_key_cipher" => OPENSSL_CIPHER_AES_256_CBC
        ];
        
        // Try with minimal config first
        $res = openssl_pkey_new($config);
        
        // If that fails, try with OpenSSL config file
        if (!$res) {
            $configFile = $this->getOpenSSLConfigPath();
            if ($configFile && file_exists($configFile)) {
                $config["config"] = $configFile;
                $res = openssl_pkey_new($config);
            }
        }
        
        // If still fails, try with even more basic config
        if (!$res) {
            $basicConfig = [
                "digest_alg" => "sha256",
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            ];
            $res = openssl_pkey_new($basicConfig);
        }
        
        if (!$res) {
            // Log the actual OpenSSL error
            $errors = [];
            while (($error = openssl_error_string()) !== false) {
                $errors[] = $error;
            }
            $errorMsg = empty($errors) ? 'Unknown OpenSSL error' : implode(', ', $errors);
            throw new Exception('Failed to generate RSA key pair: ' . $errorMsg);
        }
        
        $privateKey = '';
        $exportResult = openssl_pkey_export($res, $privateKey);
        
        if (!$exportResult) {
            $errors = [];
            while (($error = openssl_error_string()) !== false) {
                $errors[] = $error;
            }
            $errorMsg = empty($errors) ? 'Unknown OpenSSL error' : implode(', ', $errors);
            throw new Exception('Failed to export private key: ' . $errorMsg);
        }
        
        $publicKeyDetails = openssl_pkey_get_details($res);
        if (!$publicKeyDetails) {
            throw new Exception('Failed to get public key details');
        }
        
        return [
            'private' => $privateKey,
            'public' => $publicKeyDetails["key"]
        ];
    }
    
    /**
     * Get OpenSSL configuration file path
     */
    private function getOpenSSLConfigPath() {
        $possiblePaths = [
            __DIR__ . '/openssl.cnf',  // Our custom config file
            'C:/xampp/apache/bin/openssl.cnf',
            'C:/xampp/php/extras/openssl/openssl.cnf',
            'C:/OpenSSL/openssl.cnf',
            'C:/Program Files/OpenSSL/openssl.cnf',
            'C:/Program Files (x86)/OpenSSL/openssl.cnf'
        ];
        
        foreach ($possiblePaths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }
        
        return null;
    }
    
    /**
     * Advanced multi-layer encryption
     */
    public function encrypt($data, $password, $publicKey = null) {
        try {
            // Layer 1: Generate salt and derive key
            $salt = $this->generateSecureRandom($this->saltLength);
            $masterKey = $this->deriveKey($password, $salt);
            
            // Layer 2: AES-256-GCM encryption
            $iv = $this->generateSecureRandom(12); // GCM recommended IV length
            $tag = '';
            
            $encrypted = openssl_encrypt(
                $data,
                'aes-256-gcm',
                $masterKey,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );
            
            if ($encrypted === false) {
                throw new Exception('AES encryption failed: ' . openssl_error_string());
            }
            
            // Layer 3: XOR obfuscation with random key
            $xorKey = $this->generateSecureRandom(strlen($encrypted));
            $xorEncrypted = $this->xorEncrypt($encrypted, $xorKey);
            
            // Layer 4: RSA encryption of AES key (if public key provided)
            $keyPackage = null;
            if ($publicKey) {
                $keyData = base64_encode($masterKey . $iv . $tag . $xorKey);
                $keyEncrypted = '';
                if (!openssl_public_encrypt($keyData, $keyEncrypted, $publicKey)) {
                    throw new Exception('RSA encryption failed: ' . openssl_error_string());
                }
                $keyPackage = base64_encode($keyEncrypted);
            }
            
            // Layer 5: Multiple encoding layers
            $encoded = base64_encode($xorEncrypted);
            $hexEncoded = bin2hex($encoded);
            $finalEncoded = base64_encode($hexEncoded);
            
            // Create final package
            $package = [
                'data' => $finalEncoded,
                'salt' => base64_encode($salt),
                'iterations' => $this->pbkdf2Iterations,
                'algorithm' => 'aes-256-gcm-rsa-pbkdf2-xor-multi',
                'timestamp' => time(),
                'version' => '1.0'
            ];
            
            if ($keyPackage) {
                $package['key_package'] = $keyPackage;
            }
            
            return json_encode($package);
            
        } catch (Exception $e) {
            throw new Exception('Encryption failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Advanced multi-layer decryption
     */
    public function decrypt($encryptedData, $password, $privateKey = null) {
        try {
            $package = json_decode($encryptedData, true);
            if (!$package) {
                throw new Exception('Invalid encrypted data format');
            }
            
            // Extract components
            $salt = base64_decode($package['salt']);
            $iterations = $package['iterations'] ?? $this->pbkdf2Iterations;
            
            // Layer 1: Derive key
            $masterKey = $this->deriveKey($password, $salt, $iterations);
            
            // Layer 2: Decode data
            $finalEncoded = $package['data'];
            $hexDecoded = hex2bin(base64_decode($finalEncoded));
            $base64Decoded = base64_decode($hexDecoded);
            
            // Layer 3: Handle RSA decryption if key package exists
            $keyComponents = null;
            if (isset($package['key_package']) && $privateKey) {
                $keyEncrypted = base64_decode($package['key_package']);
                $keyDecrypted = '';
                if (!openssl_private_decrypt($keyEncrypted, $keyDecrypted, $privateKey)) {
                    throw new Exception('RSA decryption failed: ' . openssl_error_string());
                }
                $keyComponents = base64_decode($keyDecrypted);
            }
            
            // Layer 4: XOR decryption
            $xorKey = '';
            if ($keyComponents) {
                $xorKey = substr($keyComponents, -32); // Last 32 bytes
                $iv = substr($keyComponents, 32, 12); // 12 bytes for IV
                $tag = substr($keyComponents, 44, 16); // 16 bytes for tag
            } else {
                // Fallback: extract from data (less secure)
                $xorKey = substr($base64Decoded, -32);
                $dataWithoutKey = substr($base64Decoded, 0, -32);
                $iv = substr($dataWithoutKey, -12);
                $encryptedData = substr($dataWithoutKey, 0, -12);
                $tag = substr($encryptedData, -16);
                $encryptedData = substr($encryptedData, 0, -16);
                $base64Decoded = $encryptedData;
            }
            
            $xorDecrypted = $this->xorEncrypt($base64Decoded, $xorKey);
            
            // Layer 5: AES decryption
            $decrypted = openssl_decrypt(
                $xorDecrypted,
                'aes-256-gcm',
                $masterKey,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );
            
            if ($decrypted === false) {
                throw new Exception('AES decryption failed: ' . openssl_error_string());
            }
            
            return $decrypted;
            
        } catch (Exception $e) {
            throw new Exception('Decryption failed: ' . $e->getMessage());
        }
    }
    
    /**
     * XOR encryption/decryption (symmetric operation)
     */
    private function xorEncrypt($data, $key) {
        $result = '';
        $keyLength = strlen($key);
        
        for ($i = 0; $i < strlen($data); $i++) {
            $result .= $data[$i] ^ $key[$i % $keyLength];
        }
        
        return $result;
    }
    
    /**
     * Generate secure password hash
     */
    public function hashPassword($password) {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);
    }
    
    /**
     * Verify password hash
     */
    public function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    /**
     * Enhanced encryption without RSA (fallback method)
     */
    public function encryptWithoutRSA($data, $password) {
        try {
            // Layer 1: Generate salt and derive key
            $salt = $this->generateSecureRandom($this->saltLength);
            $masterKey = $this->deriveKey($password, $salt);
            
            // Layer 2: AES-256-GCM encryption
            $iv = $this->generateSecureRandom(12);
            $tag = '';
            
            $encrypted = openssl_encrypt(
                $data,
                'aes-256-gcm',
                $masterKey,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );
            
            if ($encrypted === false) {
                throw new Exception('AES encryption failed: ' . openssl_error_string());
            }
            
            // Layer 3: Triple XOR obfuscation with multiple keys
            $xorKey1 = $this->generateSecureRandom(32); // Fixed 32-byte keys
            $xorKey2 = $this->generateSecureRandom(32);
            $xorKey3 = $this->generateSecureRandom(32);
            
            $xorEncrypted1 = $this->xorEncrypt($encrypted, $xorKey1);
            $xorEncrypted2 = $this->xorEncrypt($xorEncrypted1, $xorKey2);
            $xorEncrypted3 = $this->xorEncrypt($xorEncrypted2, $xorKey3);
            
            // Layer 4: Additional encryption with derived key
            $additionalKey = hash('sha256', $password . $salt, true);
            $finalEncrypted = $this->xorEncrypt($xorEncrypted3, $additionalKey);
            
            // Layer 5: Multiple encoding layers with obfuscation
            $encoded = base64_encode($finalEncrypted);
            $hexEncoded = bin2hex($encoded);
            $base64Again = base64_encode($hexEncoded);
            $hexAgain = bin2hex($base64Again);
            $finalEncoded = base64_encode($hexAgain);
            
            // Create final package with all keys embedded
            $keyPackage = base64_encode($iv . $tag . $xorKey1 . $xorKey2 . $xorKey3);
            
            $package = [
                'data' => $finalEncoded,
                'keys' => $keyPackage,
                'salt' => base64_encode($salt),
                'iterations' => $this->pbkdf2Iterations,
                'algorithm' => 'aes-256-gcm-pbkdf2-triple-xor-enhanced',
                'timestamp' => time(),
                'version' => '1.1'
            ];
            
            return json_encode($package);
            
        } catch (Exception $e) {
            throw new Exception('Enhanced encryption failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Enhanced decryption without RSA (fallback method)
     */
    public function decryptWithoutRSA($encryptedData, $password) {
        try {
            $package = json_decode($encryptedData, true);
            if (!$package) {
                throw new Exception('Invalid encrypted data format');
            }
            
            // Extract components
            $salt = base64_decode($package['salt']);
            $iterations = $package['iterations'] ?? $this->pbkdf2Iterations;
            $keyPackage = base64_decode($package['keys']);
            
            // Layer 1: Derive key
            $masterKey = $this->deriveKey($password, $salt, $iterations);
            
            // Layer 2: Decode data
            $finalEncoded = $package['data'];
            $hexDecoded = hex2bin(base64_decode($finalEncoded));
            $base64Decoded = base64_decode($hexDecoded);
            $hexDecoded2 = hex2bin($base64Decoded);
            $base64Decoded2 = base64_decode($hexDecoded2);
            
            // Layer 3: Extract keys and components
            $iv = substr($keyPackage, 0, 12);
            $tag = substr($keyPackage, 12, 16);
            $xorKey1 = substr($keyPackage, 28, 32);
            $xorKey2 = substr($keyPackage, 60, 32);
            $xorKey3 = substr($keyPackage, 92, 32);
            
            
            // Layer 4: Reverse XOR operations
            $additionalKey = hash('sha256', $password . $salt, true);
            $xorDecrypted1 = $this->xorEncrypt($base64Decoded2, $additionalKey);
            $xorDecrypted2 = $this->xorEncrypt($xorDecrypted1, $xorKey3);
            $xorDecrypted3 = $this->xorEncrypt($xorDecrypted2, $xorKey2);
            $xorDecrypted4 = $this->xorEncrypt($xorDecrypted3, $xorKey1);
            
            // Layer 5: AES decryption
            $decrypted = openssl_decrypt(
                $xorDecrypted4,
                'aes-256-gcm',
                $masterKey,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );
            
            if ($decrypted === false) {
                throw new Exception('AES decryption failed: ' . openssl_error_string());
            }
            
            return $decrypted;
            
        } catch (Exception $e) {
            throw new Exception('Enhanced decryption failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Check if RSA is available
     */
    public function isRSAAvailable() {
        try {
            $testConfig = [
                "digest_alg" => "sha256",
                "private_key_bits" => 1024,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            ];
            
            $res = openssl_pkey_new($testConfig);
            if ($res) {
                openssl_pkey_free($res);
                return true;
            }
            return false;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Encrypt file with enhanced encryption
     */
    public function encryptFile($fileContent, $filename, $password) {
        try {
            // Add filename to the data for recovery
            // Use base64 encoding for binary content to avoid JSON encoding issues
            $fileData = [
                'filename' => $filename,
                'content' => base64_encode($fileContent), // Encode binary content as base64
                'size' => strlen($fileContent),
                'timestamp' => time(),
                'binary' => true // Flag to indicate this is binary content
            ];
            
            $dataString = json_encode($fileData);
            return $this->encryptWithoutRSA($dataString, $password);
            
        } catch (Exception $e) {
            throw new Exception('File encryption failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Decrypt file with enhanced encryption
     */
    public function decryptFile($encryptedData, $password) {
        try {
            // First, try to decrypt the data directly
            $decryptedString = $this->decryptWithoutRSA($encryptedData, $password);
            
            // Try to parse as JSON
            $fileData = json_decode($decryptedString, true);
            
            if (!$fileData) {
                $jsonError = json_last_error_msg();
                
                // Check if this looks like a wrong password (garbled data)
                if (strlen($decryptedString) > 0 && !preg_match('/^[\x20-\x7E]*$/', $decryptedString)) {
                    throw new Exception('Decryption failed - this appears to be the wrong password. The decrypted data contains non-printable characters, which suggests an incorrect password was used.');
                }
                
                throw new Exception('Failed to parse JSON: ' . $jsonError . ' - Data: ' . substr($decryptedString, 0, 200) . '... (Length: ' . strlen($decryptedString) . ')');
            }
            
            if (!isset($fileData['filename']) || !isset($fileData['content'])) {
                $availableKeys = array_keys($fileData);
                throw new Exception('Invalid encrypted file format - missing filename or content. Available keys: ' . implode(', ', $availableKeys));
            }
            
            // Decode binary content if it was base64 encoded
            $content = $fileData['content'];
            if (isset($fileData['binary']) && $fileData['binary']) {
                $content = base64_decode($fileData['content']);
            }
            
            return [
                'filename' => $fileData['filename'],
                'content' => $content,
                'size' => $fileData['size'] ?? strlen($content),
                'timestamp' => $fileData['timestamp'] ?? time()
            ];
            
        } catch (Exception $e) {
            throw new Exception('File decryption failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Get encryption info
     */
    public function getEncryptionInfo() {
        return [
            'aes_key_length' => $this->aesKeyLength * 8,
            'rsa_key_size' => $this->rsaKeySize,
            'pbkdf2_iterations' => $this->pbkdf2Iterations,
            'salt_length' => $this->saltLength * 8,
            'rsa_available' => $this->isRSAAvailable(),
            'algorithms' => ['AES-256-GCM', 'RSA-4096', 'PBKDF2-SHA512', 'XOR', 'Base64', 'Hex']
        ];
    }
}

?>
