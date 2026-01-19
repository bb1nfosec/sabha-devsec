# SABHA-DevSec: Notifications & DevSecOps - Quick Start

## ✅ What's Been Added

### **1. Notification System** (`notifications.js`)
- Slack webhook support with rich blocks
- Microsoft Teams adaptive cards  
- Generic webhooks (Discord, custom)
- Threshold-based alerting
- Notification history log

### **2. Storage & Trends** (`storage.js`)
- Scan history (last 30 scans)
- Trend analysis & comparison
- Settings persistence (LocalStorage)
- Export/Import configuration

### **3. Next: Settings UI**
Adding a Settings panel where you can:
- Configure Slack/Teams webhooks
- Set alert thresholds
- Test notifications
- View notification log
- Manage scan history

---

## 🚀 How to Use (After Settings UI is Complete)

### **Configure Slack Notifications**:
1. In SABHA-DevSec, click ⚙️ Settings
2. Go to "Notifications" tab
3. Enter your Slack webhook URL
4. Set threshold (e.g., alert if >= 3 critical findings)
5. Click "Test Slack" to verify
6. Enable notifications

### **Configure Teams Notifications**:
Same process, but with Teams webhook URL

### **Automatic Alerts**:
Once configured, SABHA-DevSec will automatically send notifications when:
- Critical findings exceed threshold
- Security Debt Score is too high
- After every scan (if enabled)
- Trend is worsening vs previous scan

---

## 📊 CI/CD Integration (Coming Next)

**GitHub Actions Example**:
```yaml
- name: Upload to SABHA-DevSec
  run: |
    curl -X POST http://your-sabha-instance \
      -F "file=@scan-results.json"
```

The platform will automatically analyze and notify your team in Slack/Teams!

---

**Status**: Phase 1 (Notifications) - 70% Complete  
**Next**: Adding Settings UI Component (15 min)
