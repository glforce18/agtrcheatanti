# Security Policy

## 🔒 Security & Privacy

### Our Commitment

AGTR Anti-Cheat is committed to protecting user privacy and maintaining system security. This document outlines what we collect, what we don't collect, and how we handle security issues.

---

## ✅ What We Collect

We collect **ONLY** game-related information necessary for anti-cheat functionality:

| Data Type | Purpose | Example | Personal Info? |
|-----------|---------|---------|----------------|
| **HWID** | Unique player identification | `ABC123...` (SHA256 hash) | ❌ No - Anonymous |
| **Process Names** | Cheat detection | `cheatengine.exe` | ❌ No |
| **DLL Modules** | Injection detection | `suspicious.dll` | ❌ No |
| **Server IP/Port** | Tracking play location | `185.171.25.137:27015` | ❌ No |
| **Game Screenshots** | Admin verification only | Game window capture | ⚠️ Limited - Game only |

### HWID Composition

Hardware ID is created from:
```
CPU ID (CPUID instruction)
  + MAC Address
  + Volume Serial Number
  + Windows Product ID
  → SHA256 Hash (64 characters)
  → Anonymous identifier
```

**No personal information is included in HWID.**

---

## ❌ What We DO NOT Collect

We **NEVER** collect:

- ❌ **Passwords** (browser, game, system)
- ❌ **Credit card information** or payment details
- ❌ **Personal files** (documents, photos, videos)
- ❌ **Browser history** or bookmarks
- ❌ **Keystrokes** (no keylogger)
- ❌ **Desktop screenshots** (only game window when admin requests)
- ❌ **Chat messages** or communications
- ❌ **Email addresses** (unless you contact us)
- ❌ **Real names** or personal identities
- ❌ **File contents** (we only check file hashes)

---

## 🔐 Data Security

### Encryption

- **In-Transit:** AES-256 encryption for all API communication
- **HTTPS:** All backend communication over encrypted connection
- **Hash-Only:** File scanning uses MD5 hashes, not file contents

### Storage

- **HWID:** Stored hashed, not reversible to hardware info
- **Scan Results:** Stored for admin review, deleted after 90 days
- **No Cloud Storage:** All data on our backend server only
- **No Third-Party:** No data sharing with third parties

### Access Control

- **Admin Only:** Scan results accessible only to authorized server admins
- **No Public Data:** Player scan results are never public
- **Secure Backend:** Backend API requires authentication

---

## 🐛 Reporting Security Issues

### Responsible Disclosure

If you discover a security vulnerability, please report it responsibly:

#### DO:
- ✅ Email us privately at: **security@yourdomain.com** (replace with actual email)
- ✅ Provide detailed reproduction steps
- ✅ Give us reasonable time to fix (90 days)
- ✅ Act in good faith

#### DON'T:
- ❌ Publicly disclose before we've fixed it
- ❌ Exploit the vulnerability maliciously
- ❌ Demand payment or extort

### Reward Program

We appreciate security researchers! Valid security reports may be eligible for:

| Severity | Description | Reward |
|----------|-------------|--------|
| **Critical** | Remote code execution, credential theft | $200 |
| **High** | Arbitrary file read, memory corruption | $100 |
| **Medium** | Logic bugs, DoS | $50 |
| **Low** | Information disclosure, cosmetic | $25 |

*Rewards are discretionary and depend on severity, impact, and quality of report.*

---

## 🔍 Verification Methods

### How to Verify Safety

You can verify AGTR's safety yourself:

#### 1. **Source Code Review**
- All code is on GitHub: https://github.com/glforce18/agtrcheatanti
- Search for suspicious patterns:
  - `password`, `credential`, `keylog`
  - `credit`, `bank`, `payment`
  - File operations outside game folder

#### 2. **VirusTotal Scan**
- Upload DLL to https://www.virustotal.com/
- Expected result: 0 or minimal false positives
- Check community comments

#### 3. **Network Traffic Analysis**
- Use Wireshark to monitor traffic
- Expected: Only HTTPS to our backend API
- No traffic to unknown servers

#### 4. **File Access Monitoring**
- Use Process Monitor (Sysinternals)
- Expected: Only accesses to game folder
- No access to Documents, Desktop, AppData (except logs)

#### 5. **Build from Source**
- Clone repository
- Compile yourself with Visual Studio
- Use your own compiled DLL

---

## 🚨 Known False Positives

### Antivirus Detections

Some antivirus software may flag AGTR as suspicious due to:

1. **DLL Proxy Method** - Intercepting game DLL loading
2. **Heuristic Detection** - Scanning processes and memory
3. **Packer Detection** - Some compilers produce suspicious signatures

**This is a FALSE POSITIVE.**

### How to Handle:

- ✅ Scan with VirusTotal (multiple engines)
- ✅ Review source code on GitHub
- ✅ Add exception to your antivirus
- ✅ Build from source yourself

### Reported False Positives:

| Antivirus | Detection | Status |
|-----------|-----------|--------|
| Windows Defender | Usually clean | ✅ Safe |
| Avast | Generic:Trojan | ⚠️ False Positive |
| AVG | Generic | ⚠️ False Positive |
| Malwarebytes | Usually clean | ✅ Safe |

*Note: Detection varies by AV version and heuristic rules*

---

## 📋 Security Checklist

Before downloading AGTR, verify:

- [ ] GitHub repository is official: `github.com/glforce18/agtrcheatanti`
- [ ] Release is signed and from Actions artifacts
- [ ] VirusTotal scan shows acceptable results
- [ ] Source code is reviewable and matches release
- [ ] Community feedback is positive

---

## 🔄 Security Updates

### Update Policy

- Security fixes are released **immediately**
- All users notified via GitHub and Discord (if applicable)
- Auto-update system (optional) keeps DLL current
- Changelog includes security notes

### Version Support

| Version | Status | Security Updates |
|---------|--------|------------------|
| v14.1.2+ | ✅ Active | Yes |
| v14.0-14.1.1 | ⚠️ Old | Critical only |
| v13.x | ❌ Deprecated | No |
| v12.x and older | ❌ Unsupported | No |

---

## 📞 Contact

### General Security Questions
- GitHub Discussions: https://github.com/glforce18/agtrcheatanti/discussions
- GitHub Issues: https://github.com/glforce18/agtrcheatanti/issues

### Private Security Reports
- Email: **security@yourdomain.com** (replace with actual)
- PGP Key: *(optional - provide if available)*

### Response Time
- **Critical:** Within 24 hours
- **High:** Within 3 days
- **Medium/Low:** Within 1 week

---

## 📜 Compliance

### GDPR Compliance (EU Users)

- **Right to Access:** Request your stored data
- **Right to Deletion:** Request data removal
- **Right to Portability:** Export your data
- **Data Minimization:** We collect only necessary data

### Your Rights

You have the right to:
1. Know what data we store about you
2. Request deletion of your data
3. Opt-out of data collection (results in ban)
4. Access your stored scan results

Contact us to exercise these rights.

---

## ✅ Trust & Transparency

### Open Source Advantage

**"Don't trust, verify!"**

Open source means:
- Every line of code is reviewable
- No hidden backdoors possible
- Community oversight
- Reproducible builds

### Accountability

We are accountable to:
- **Users:** Can review code and report issues
- **Community:** Public development on GitHub
- **Security Researchers:** Responsible disclosure program
- **Server Owners:** Transparent operation

---

**Last Updated:** 2026-01-27
**Version:** 14.1.2
**Maintainer:** AGTR Development Team

---

*Remember: Security is a process, not a product. We continuously improve and welcome your feedback.*

**🔍 Verify, don't just trust. Read the code yourself.**
