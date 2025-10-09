# 🔐 Advanced File Encryptor with Admin Protection

A professional-grade file encryption system with separated encryption/decryption access and admin password protection.

## 🌟 Features

### 🔓 **Encryption (Public Access)**
- ✅ **No login required** - Anyone can encrypt files
- ✅ **Text encryption** - Encrypt plain text messages
- ✅ **File encryption** - Encrypt any file type
- ✅ **Drag & drop** interface
- ✅ **Password-based** encryption

### 🔐 **Decryption (Admin Only)**
- ✅ **Admin password required** - Secure access control
- ✅ **Text decryption** - Decrypt encrypted messages
- ✅ **File decryption** - Decrypt encrypted files
- ✅ **Session management** - Secure admin sessions
- ✅ **Logout functionality** - End admin access

### 🛡️ **Security Features**
- ✅ **AES-256-GCM** - Military-grade encryption
- ✅ **PBKDF2-SHA512** - 100,000 iterations
- ✅ **Triple XOR obfuscation** - Extra security layer
- ✅ **Multi-layer encoding** - Base64 + Hex
- ✅ **Admin password hashing** - PBKDF2-SHA512 with 100K iterations
- ✅ **Config file encryption** - AES-256-CBC
- ✅ **Permanent password lock** - Cannot be changed after setup
- ✅ **No database required** - Secure file-based storage

## 📁 File Structure

```
encryptor/
├── encrypt.php           # Encryption page (no login required)
├── decrypt.php           # Decryption page (admin required)
├── admin_login.php       # Admin login page
├── setup.php             # First-time admin setup (one-time only)
├── logout.php            # Admin logout
├── admin_auth.php        # Admin authentication class
├── api.php               # Backend API for encryption/decryption
├── encryption.php        # Core encryption logic
├── openssl.cnf           # OpenSSL configuration
├── admin_config.enc      # Admin config (auto-generated, encrypted)
├── admin_lock.dat        # Password lock file (auto-generated)
└── README.md             # This file
```

## 🚀 Getting Started

### 1️⃣ **First-Time Setup**

When you first visit the decryption page, you'll be redirected to the setup page:

1. Visit: `http://localhost/encryptor/decrypt.php`
2. You'll be redirected to `setup.php`
3. Enter your desired admin password (min 8 characters)
4. Confirm the password
5. Click "Set Admin Password (Permanent)"

**⚠️ CRITICAL:** This password is **PERMANENTLY LOCKED** and cannot be changed!

### 2️⃣ **Encryption (No Login)**

1. Visit: `http://localhost/encryptor/encrypt.php`
2. **Text Encryption:**
   - Enter text to encrypt
   - Enter a password
   - Click "Encrypt Text"
   - Copy the encrypted result
3. **File Encryption:**
   - Drag & drop a file (or click "Select New File")
   - Enter a password
   - Click "Encrypt File"
   - Download the `.enc` file

### 3️⃣ **Decryption (Admin Required)**

1. Visit: `http://localhost/encryptor/decrypt.php`
2. Enter your admin password
3. Click "Login to Decrypt"
4. **Text Decryption:**
   - Paste encrypted text
   - Enter the encryption password
   - Click "Decrypt Text"
5. **File Decryption:**
   - Drag & drop `.enc` file (or click "Select New File")
   - Enter the encryption password
   - Click "Decrypt File"
   - Download the decrypted file

## 🔒 Admin Password System

### **How It Works:**

1. **First Setup:** Admin password must be set on first use
2. **Permanent Lock:** Once set, the password **CANNOT** be changed
3. **File Storage:** Admin config stored in encrypted file (`admin_config.enc`)
4. **Lock File:** `admin_lock.dat` marks the password as permanently locked
5. **No Database:** Everything stored in secure files

### **Password Reset (Manual):**

If you forget the admin password, you must:

1. Stop your web server
2. Delete `admin_config.enc`
3. Delete `admin_lock.dat`
4. Restart your web server
5. Visit setup page again to set a new password

**⚠️ Warning:** This will reset admin access. Encrypted files remain safe.

## 🔐 Security Analysis

### **Password Strength:**

With a **20-character password** (letters + numbers + special chars):

- **Possible combinations:** 94^20 = 2.9 × 10^39
- **Brute force time (with PBKDF2):** > 10^19 years
- **Security level:** Military-grade

### **Attack Resistance:**

✅ **Brute Force:** Practically impossible  
✅ **Dictionary Attack:** Highly resistant  
✅ **Rainbow Tables:** Completely blocked by salt  
✅ **Timing Attacks:** Mitigated by hash comparison  
✅ **Side-Channel:** Strong random generation

## 📋 Requirements

- PHP 7.4+ with OpenSSL extension
- Apache/Nginx web server
- Write permissions for config files
- Modern web browser

## 🎯 Use Cases

1. **Corporate Environment:** 
   - Employees can encrypt files freely
   - Only admins can decrypt sensitive data

2. **Secure File Sharing:**
   - Encrypt files before sending
   - Recipient needs admin access to decrypt

3. **Data Protection:**
   - Store encrypted backups
   - Decrypt only when needed with admin access

## ⚙️ Configuration

### **Admin Password Requirements:**
- Minimum 8 characters
- Recommended: 20+ characters with mixed case, numbers, symbols

### **Session Security:**
- PHP sessions with secure flags
- Automatic session cleanup on logout

### **File Permissions:**
- Config files set to read-only (0444) after creation
- Prevents accidental modification

## 🐛 Troubleshooting

### **"Encryption failed: Unexpected end of JSON input"**
- Check if `api.php` is accessible
- Verify PHP OpenSSL extension is enabled
- Check server error logs

### **"Forgot admin password"**
- Delete `admin_config.enc` and `admin_lock.dat`
- Restart web server
- Go through setup again

### **"File upload failed"**
- Check PHP upload limits in `php.ini`
- Increase `upload_max_filesize` and `post_max_size`

## 📞 Support

For issues or questions:
1. Check server error logs
2. Verify file permissions
3. Ensure OpenSSL is enabled
4. Test with small files first

## 📜 License

This is a custom encryption system. Use at your own discretion.

## ⚠️ Important Notes

1. **Admin password is permanent** - Cannot be changed after setup
2. **No database required** - All config stored in encrypted files
3. **Keep your passwords safe** - No recovery mechanism
4. **Test thoroughly** - Verify encryption/decryption before production use
5. **Backup important files** - Always keep unencrypted backups

---

**Built with military-grade encryption for maximum security** 🔐

