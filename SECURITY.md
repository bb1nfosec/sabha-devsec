# Security Policy

## 🔒 Reporting a Vulnerability

We take the security of SABHA-DevSec seriously. If you discover a security vulnerability, please report it privately to help us maintain the security and privacy of our users.

### **How to Report**

📧 **Email**: security@bb1nfosec.com

**Please include**:
- Clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fix (if you have one)

### **What to Expect**

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity (Critical: 7 days, High: 14 days, Medium: 30 days)
- **Public Disclosure**: After fix is released and users have had time to update

## 🎯 Scope

### **In Scope**:
- ✅ Cross-Site Scripting (XSS) in the application
- ✅ Data leakage or privacy violations
- ✅ Client-side security vulnerabilities
- ✅ Authentication/authorization bypasses in notification systems
- ✅ Injection vulnerabilities (if server-side implementation is added)

### **Out of Scope**:
- ❌ Social engineering attacks
- ❌ Physical access attacks
- ❌ Denial of Service (DoS) attacks
- ❌ Issues in third-party dependencies (report to maintainers)
- ❌ Theoretical attacks without practical exploit

## 🛡️ Security Features

SABHA-DevSec is designed with security and privacy as core principles:

### **Privacy-First Architecture**:
- ✅ **100% Client-Side Processing** - Your scan data never leaves your browser
- ✅ **No Backend** - No server to compromise
- ✅ **No Telemetry** - Zero data collection or analytics
- ✅ **LocalStorage Only** - Settings and scan history stored locally
- ✅ **No External Requests** - All processing happens in your browser

### **Content Security**:
- ✅ All dependencies loaded from trusted CDNs (React, Recharts, PapaParse)
- ✅ No eval() or dynamic code execution
- ✅ Input sanitization on file uploads
- ✅ XSS protection in UI rendering

### **Data Handling**:
- ✅ Scan files are processed in-memory only
- ✅ No persistent storage of sensitive scan data
- ✅ LocalStorage limited to settings and anonymized scan metadata
- ✅ Users can clear all data from Settings panel

## 🔐 Safe Harbor

We support responsible disclosure and will not take legal action against security researchers who:

1. **Act in Good Faith**
   - Make a good faith effort to avoid privacy violations
   - Do not exploit findings beyond what's necessary to demonstrate the issue
   - Give us reasonable time to address the issue before public disclosure

2. **Responsible Disclosure**
   - Report vulnerabilities privately first
   - Do not publicly disclose details until fix is released
   - Do not access or modify other users' data

3. **No Harm**
   - Do not perform actions that could harm SABHA-DevSec users
   - Do not degrade service availability
   - Respect privacy and confidentiality

## 🏆 Recognition

Security researchers who report valid vulnerabilities will be:
- ✅ Publicly acknowledged (if desired)
- ✅ Listed in our Hall of Fame
- ✅ Mentioned in release notes

## ⚠️ Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## 📝 Security Best Practices for Users

When using SABHA-DevSec:

1. **Use HTTPS** - Always access via https:// in production
2. **Keep Browser Updated** - Use latest browser versions
3. **Verify Source** - Only download from official GitHub repository
4. **Review Webhooks** - Be cautious with webhook URLs and tokens
5. **Sanitize Data** - Remove sensitive info before sharing scan files
6. **Local Hosting** - For sensitive scans, run locally rather than public demo

## 🔄 Security Update Process

When a security issue is confirmed:

1. **Acknowledgment** - Confirm receipt to reporter
2. **Investigation** - Assess severity and impact
3. **Fix Development** - Create and test security patch
4. **Private Testing** - Verify fix with reporter if appropriate
5. **Release** - Deploy fix in new version
6. **Disclosure** - Public security advisory after fix is available
7. **Recognition** - Credit reporter (with permission)

---

## 📞 Contact

**Security Team**: security@bb1nfosec.com  
**General Issues**: https://github.com/bb1nfosec/sabha-devsec/issues

---

Thank you for helping keep SABHA-DevSec and its users safe! 🔒
