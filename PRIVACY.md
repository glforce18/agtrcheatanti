# Privacy Policy

**Effective Date:** 2026-01-27
**Last Updated:** 2026-01-27
**Version:** 14.1.2

---

## 🔒 Introduction

Your privacy is important to us. This Privacy Policy explains what data AGTR Anti-Cheat collects, how we use it, and your rights regarding your data.

**TL;DR:** We only collect game-related data necessary for anti-cheat functionality. No passwords, no personal files, no browser history.

---

## 📊 Data We Collect

### 1. Hardware ID (HWID)

**What:** Anonymous hardware identifier
**How:** SHA256 hash of CPU ID + MAC + Volume Serial + Windows Product ID
**Why:** Unique player identification
**Personal:** ❌ No - Cannot be reversed to identify you

**Example:**
```
CPU ID: 12345
MAC: AA:BB:CC:DD:EE:FF
Volume Serial: 1234567890
Windows Product: XXXXX-XXXXX

→ SHA256 Hash → ABC123DEF456... (64 chars)
```

### 2. Process Names

**What:** Names of running processes
**How:** Windows API enumeration
**Why:** Cheat detection (Cheat Engine, ArtMoney, etc.)
**Personal:** ❌ No - Only process names, not window titles or content

**Example:**
```
✅ Collected: "cheatengine-x86_64.exe"
❌ NOT Collected: Window title, file content, arguments
```

### 3. Loaded Modules (DLLs)

**What:** DLL files loaded into game process
**How:** Module enumeration
**Why:** Detect injected cheats
**Personal:** ❌ No - Only filenames and hashes

**Example:**
```
✅ Collected: "suspicious.dll", hash: "A1B2C3D4"
❌ NOT Collected: DLL contents, exported functions
```

### 4. Server IP/Port

**What:** IP address and port of game server
**How:** TCP/UDP connection monitoring
**Why:** Track which server you're playing on
**Personal:** ⚠️ Limited - Server IP only, not your IP

**Example:**
```
✅ Collected: "185.171.25.137:27015"
❌ NOT Collected: Your public IP, ISP, location
```

### 5. Scan Results

**What:** Result of anti-cheat scan (pass/fail)
**How:** Automated analysis
**Why:** Admin panel display
**Personal:** ❌ No - Only binary result and counts

**Example:**
```
✅ Collected: passed=true, sus_count=0
❌ NOT Collected: Game state, player position, chat
```

### 6. Game Screenshots (Optional)

**What:** Screenshot of game window
**How:** GDI+ capture when admin requests
**Why:** Manual verification by admin
**Personal:** ⚠️ Limited - Game window only

**Example:**
```
✅ Collected: Game window content (when admin requests)
❌ NOT Collected: Desktop, other windows, taskbar
```

---

## ❌ Data We DO NOT Collect

We **explicitly do NOT** collect:

### Personal Information
- ❌ Real name, email, phone number
- ❌ Address, location, postal code
- ❌ Date of birth, age
- ❌ Gender, nationality
- ❌ Steam credentials (username/password)

### Financial Information
- ❌ Credit card numbers
- ❌ Bank account details
- ❌ PayPal, payment processor info
- ❌ Cryptocurrency wallets

### Sensitive Data
- ❌ Passwords (any kind)
- ❌ Private keys, certificates
- ❌ Authentication tokens (except our own)
- ❌ Biometric data

### File Contents
- ❌ Documents (Word, PDF, Excel)
- ❌ Photos, videos, music
- ❌ Browser history, bookmarks
- ❌ Email content
- ❌ Chat logs (Discord, Steam, etc.)

### System Information
- ❌ Clipboard content
- ❌ Keystrokes (no keylogger)
- ❌ Mouse movements
- ❌ Webcam/microphone access
- ❌ Desktop screenshots

### Network Data
- ❌ Your public IP address
- ❌ ISP information
- ❌ Network topology
- ❌ Other network connections

---

## 🎯 How We Use Data

### Anti-Cheat Detection
- Compare process names against known cheat database
- Analyze DLL modules for suspicious patterns
- Generate scan reports for admins

### Server Tracking
- Display which server player is on
- Track player activity across servers
- Server owner statistics

### Admin Panel
- Show scan history for server admins
- Allow manual review of flagged players
- Generate statistics and reports

### System Improvement
- Aggregate statistics (total scans, detection rate)
- Performance metrics (false positive rate)
- No individual user tracking for analytics

---

## 🔐 Data Security

### Encryption
- **In-Transit:** AES-256 for all API communication
- **At-Rest:** Database encryption for stored data
- **Hashing:** Irreversible SHA256 for HWID

### Access Control
- **Role-Based:** Only authorized admins can access data
- **Authentication:** API requires valid credentials
- **Audit Logs:** All access is logged

### Storage
- **Location:** Backend server (not cloud)
- **Retention:** 90 days for scan results
- **Deletion:** Automatic after retention period
- **Backup:** Encrypted offsite backups

### Security Measures
- Firewall protection
- DDoS mitigation
- Regular security audits
- Vulnerability patching

---

## 👥 Data Sharing

### We DO NOT Share Your Data

We **never** sell, rent, or share your data with:
- ❌ Third-party advertisers
- ❌ Data brokers
- ❌ Marketing companies
- ❌ Social media platforms
- ❌ Analytics services (except aggregated, anonymous)

### Limited Sharing

We may share data only in these cases:

1. **Server Admins** (your server only)
   - Your scan results
   - Server activity
   - Ban status

2. **Legal Obligation**
   - If required by law enforcement
   - With valid court order
   - To protect our legal rights

3. **Security Researchers**
   - Anonymous, aggregated data
   - With consent for security audits

---

## 🌍 International Users

### Data Transfer
- Data stored on servers in [Your Location]
- May be processed in different jurisdictions
- Same privacy protections apply everywhere

### GDPR Compliance (EU Users)

If you're in the EU, you have additional rights:
- **Right to Access:** Request your data
- **Right to Erasure:** Request deletion ("right to be forgotten")
- **Right to Portability:** Export your data
- **Right to Object:** Object to processing
- **Right to Restrict:** Limit how we use data

Contact us to exercise these rights.

---

## 👶 Children's Privacy

AGTR is not directed at children under 13 (or 16 in EU).

We do not knowingly collect data from children. If you believe we have data from a child, contact us immediately for deletion.

---

## 🍪 Cookies & Tracking

### No Browser Cookies
- We don't use browser cookies
- No web tracking
- No advertising pixels

### Game Client Tracking
- HWID for player identification
- Session tracking for anti-cheat
- No cross-site tracking

---

## 🔄 Data Retention

| Data Type | Retention Period | Reason |
|-----------|------------------|--------|
| Scan Results | 90 days | Admin review, statistics |
| HWID | Until account deletion | Player identification |
| Ban Records | Permanent | Security, prevent evasion |
| Logs | 30 days | Debugging, security |

### Automatic Deletion
- Scan results older than 90 days are auto-deleted
- Logs older than 30 days are purged
- Inactive accounts (1 year+) may be archived

### Manual Deletion
You can request deletion of your data at any time (except active bans).

---

## 📧 Your Rights

You have the right to:

### Access
- Request a copy of your stored data
- See what scans we have on record
- View your HWID

### Correction
- Update incorrect information
- Correct scan results (if error)

### Deletion
- Request deletion of your data
- "Right to be forgotten"
- May result in ban if you continue playing

### Portability
- Export your data in JSON format
- Transfer to another service (if applicable)

### Object
- Object to data processing
- Opt-out (results in ban)

### Complaint
- File complaint with supervisory authority
- Contact us first to resolve

---

## 📞 Contact for Privacy Concerns

### Data Requests
Email: privacy@yourdomain.com (replace with actual)

Include:
- Your HWID (if known)
- Server you play on
- Nature of request

### Response Time
- **Data Access:** 30 days
- **Data Deletion:** 7 days
- **General Questions:** 5 business days

---

## 🔄 Policy Updates

### Change Notification
- Major changes: Email notification (if we have it)
- Minor changes: GitHub commit
- Always check this file for latest version

### Version History
- v1.0 (2026-01-27): Initial privacy policy

### Acceptance
Continuing to use AGTR after policy changes means you accept the new policy.

---

## 📜 Legal Basis for Processing (GDPR)

We process your data based on:

1. **Consent:** You install and use AGTR voluntarily
2. **Legitimate Interest:** Anti-cheat protection for all players
3. **Contractual Necessity:** Required for game server participation

---

## 🔍 Transparency Report

We believe in transparency. Annually, we publish:
- Number of data requests received
- Law enforcement requests
- Data breaches (if any)
- Security incidents

*No reports published yet - first year*

---

## ✅ Summary

**What We Collect:**
- HWID (anonymous)
- Process names
- DLL modules
- Server IP/Port
- Scan results

**What We DON'T Collect:**
- Passwords
- Personal files
- Browser history
- Financial info
- Keystrokes

**How We Protect:**
- AES-256 encryption
- Secure storage
- Access control
- Regular audits

**Your Rights:**
- Access your data
- Request deletion
- Export your data
- File complaints

---

**Questions?** Read our [Security Policy](SECURITY.md) or [README](README.md)

**Don't trust, verify!** Source code: https://github.com/glforce18/agtrcheatanti

---

**Last Updated:** 2026-01-27
**Effective Date:** 2026-01-27
**Version:** 14.1.2
**Contact:** privacy@yourdomain.com (replace with actual)
