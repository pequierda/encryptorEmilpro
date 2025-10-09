# EmilPro Encryptor - Vercel Deployment Guide

## 🚀 Quick Deploy to Vercel

### Option 1: Deploy via Vercel CLI
```bash
npm i -g vercel
vercel
```

### Option 2: Deploy via Vercel Dashboard
1. Go to [vercel.com](https://vercel.com)
2. Click "Import Project"
3. Select your Git repository or upload this folder
4. Click "Deploy" (no build configuration needed!)

### Option 3: One-Click Deploy
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=YOUR_REPO_URL)

## 📁 Files Needed for Deployment

Only **ONE file** is required:
- ✅ `index.html` - Complete standalone encryptor

Optional files:
- `vercel.json` - Vercel configuration
- `.vercelignore` - Excludes PHP files

## ✨ What Works

✅ **100% Client-Side** - No backend needed  
✅ **AES-256-GCM Encryption** - Military-grade security  
✅ **Zero Upload** - Files never leave the browser  
✅ **Works Offline** - After first load  
✅ **.emilpro Extension** - Custom encrypted file format  
✅ **Mobile Friendly** - Responsive Tailwind design  

## 🔒 Security Features

- **Encryption**: AES-256-GCM
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Random Generation**: Crypto-secure salt/IV
- **Privacy**: Zero data collection or transmission

## 🌐 Other Deployment Options

Works on any static hosting:
- **Netlify**: Drag & drop `index.html`
- **GitHub Pages**: Push to `gh-pages` branch
- **Cloudflare Pages**: Connect repository
- **Firebase Hosting**: `firebase deploy`

## 📝 Example Usage

1. **Encrypt File**: 
   - Upload: `document.pdf`
   - Downloads: `document.pdf.emilpro`

2. **Decrypt File**:
   - Upload: `document.pdf.emilpro`
   - Downloads: `document.pdf`

## 💡 Local Testing

Simply open `index.html` in any browser - no server needed!

```bash
# Or use a simple HTTP server
python -m http.server 8000
# or
npx serve
```

Visit: `http://localhost:8000`

---

**Note**: All PHP files are excluded from Vercel deployment and are only for local XAMPP usage.

