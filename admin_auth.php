<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

class AdminAuth {
    private $configFile = 'admin_config.enc';
    private $lockFile = 'admin_lock.dat';
    
    /**
     * Check if admin password has been set
     */
    public function isPasswordSet() {
        if (!file_exists($this->configFile) || !file_exists($this->lockFile)) {
            return false;
        }
        
        // Additional security: Check if files are readable and have proper permissions
        if (!is_readable($this->configFile) || !is_readable($this->lockFile)) {
            return false;
        }
        
        // Check if files were recently modified (potential tampering detection)
        $configTime = filemtime($this->configFile);
        $lockTime = filemtime($this->lockFile);
        $currentTime = time();
        
        // If files were modified in the last 5 minutes, might be tampering
        if (($currentTime - $configTime) < 300 || ($currentTime - $lockTime) < 300) {
            // Log potential tampering attempt
            error_log("Potential admin config tampering detected at " . date('Y-m-d H:i:s'));
        }
        
        return true;
    }
    
    /**
     * Check if admin is locked (first-time setup complete)
     */
    public function isLocked() {
        return file_exists($this->lockFile);
    }
    
    /**
     * Set admin password (ONLY works on first-time setup)
     */
    public function setPassword($password) {
        // Check if already locked - if locked, CANNOT change password
        if ($this->isLocked()) {
            throw new Exception('Admin password is permanently locked and cannot be changed.');
        }
        
        // Security check: Verify we're in a legitimate setup process
        if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
            throw new Exception('Invalid setup method.');
        }
        
        // Validate password strength
        if (strlen($password) < 8) {
            throw new Exception('Password must be at least 8 characters long.');
        }
        
        // Hash the password with strong encryption
        $salt = bin2hex(random_bytes(32));
        $hash = hash_pbkdf2('sha512', $password, $salt, 100000, 64);
        
        // Store encrypted password
        $data = json_encode([
            'hash' => $hash,
            'salt' => $salt,
            'created' => time(),
            'version' => '1.0'
        ]);
        
        // Encrypt the config file itself
        $encryptedData = $this->encryptConfig($data);
        
        if (!file_put_contents($this->configFile, $encryptedData)) {
            throw new Exception('Failed to save admin configuration.');
        }
        
        // Create lock file - this makes password permanent
        if (!file_put_contents($this->lockFile, json_encode([
            'locked' => true,
            'locked_at' => time(),
            'message' => 'Admin password is permanently locked'
        ]))) {
            throw new Exception('Failed to create lock file.');
        }
        
        // Set file permissions to read-only
        @chmod($this->configFile, 0444);
        @chmod($this->lockFile, 0444);
        
        return true;
    }
    
    /**
     * Verify admin password
     */
    public function verifyPassword($password) {
        if (!$this->isPasswordSet()) {
            return false;
        }
        
        // Read encrypted config
        $encryptedData = file_get_contents($this->configFile);
        if (!$encryptedData) {
            return false;
        }
        
        // Decrypt config
        $data = $this->decryptConfig($encryptedData);
        if (!$data) {
            return false;
        }
        
        $config = json_decode($data, true);
        if (!$config || !isset($config['hash']) || !isset($config['salt'])) {
            return false;
        }
        
        // Verify password
        $hash = hash_pbkdf2('sha512', $password, $config['salt'], 100000, 64);
        
        return hash_equals($config['hash'], $hash);
    }
    
    /**
     * Login admin
     */
    public function login($password) {
        if ($this->verifyPassword($password)) {
            // Regenerate session ID for security
            session_regenerate_id(true);
            
            $_SESSION['admin_authenticated'] = true;
            $_SESSION['admin_login_time'] = time();
            $_SESSION['admin_last_activity'] = time();
            return true;
        }
        return false;
    }
    
    /**
     * Check if admin is logged in
     */
    public function isLoggedIn() {
        if (!isset($_SESSION['admin_authenticated']) || $_SESSION['admin_authenticated'] !== true) {
            return false;
        }
        
        // Check session timeout (30 minutes of inactivity)
        $timeout = 30 * 60; // 30 minutes in seconds
        if (isset($_SESSION['admin_login_time']) && (time() - $_SESSION['admin_login_time']) > $timeout) {
            $this->logout();
            return false;
        }
        
        // Update last activity time
        $_SESSION['admin_last_activity'] = time();
        
        return true;
    }
    
    /**
     * Logout admin - Complete session cleanup
     */
    public function logout() {
        // Clear all session variables
        $_SESSION = array();
        
        // Delete the session cookie
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        
        // Destroy the session
        session_destroy();
        
        // Start a new session to prevent session fixation
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Regenerate session ID for security
        session_regenerate_id(true);
        
        // Clear the new session
        $_SESSION = array();
        
        // Set logout flag for debugging
        $_SESSION['logout_completed'] = true;
    }
    
    /**
     * Get admin status info
     */
    public function getStatus() {
        return [
            'password_set' => $this->isPasswordSet(),
            'locked' => $this->isLocked(),
            'logged_in' => $this->isLoggedIn(),
            'can_change_password' => !$this->isLocked()
        ];
    }
    
    /**
     * Simple encryption for config file
     */
    private function encryptConfig($data) {
        // Use a system-specific key (not user password)
        $systemKey = hash('sha256', __DIR__ . $_SERVER['HTTP_HOST'] . 'admin_secret_key', true);
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'aes-256-cbc', $systemKey, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Simple decryption for config file
     */
    private function decryptConfig($encryptedData) {
        $systemKey = hash('sha256', __DIR__ . $_SERVER['HTTP_HOST'] . 'admin_secret_key', true);
        $data = base64_decode($encryptedData);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'aes-256-cbc', $systemKey, OPENSSL_RAW_DATA, $iv);
    }
}
?>

