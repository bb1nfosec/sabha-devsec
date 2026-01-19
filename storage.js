// SABHA-DevSec Storage Manager
// Handles scan history, settings, and trend analysis

class StorageManager {
    constructor() {
        this.scanHistory = this.loadScanHistory();
        this.settings = this.loadSettings();
    }

    // ============================================================================
    // SCAN HISTORY
    // ============================================================================

    loadScanHistory() {
        try {
            const saved = localStorage.getItem('sabha_scan_history');
            return saved ? JSON.parse(saved) : [];
        } catch (e) {
            return [];
        }
    }

    saveScanHistory() {
        // Keep only last 30 scans
        if (this.scanHistory.length > 30) {
            this.scanHistory = this.scanHistory.slice(-30);
        }
        localStorage.setItem('sabha_scan_history', JSON.stringify(this.scanHistory));
    }

    addScan(analysis) {
        const scan = {
            id: this.generateId(),
            timestamp: analysis.timestamp,
            fileName: analysis.fileName || 'Unknown',
            metrics: analysis.metrics,
            securityDebtScore: analysis.securityDebtScore,
            topDomain: analysis.riskDomains[0]?.domain || null,
            totalDomains: analysis.riskDomains.length,
            financialExposure: analysis.riskDomains[0]?.exposure || 'N/A'
        };

        this.scanHistory.push(scan);
        this.saveScanHistory();
        return scan;
    }

    getScanHistory() {
        return this.scanHistory.slice().reverse(); // Most recent first
    }

    getLatestScan() {
        return this.scanHistory[this.scanHistory.length - 1] || null;
    }

    getPreviousScan() {
        return this.scanHistory[this.scanHistory.length - 2] || null;
    }

    clearHistory() {
        this.scanHistory = [];
        this.saveScanHistory();
    }

    generateId() {
        return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    // ============================================================================
    // TREND ANALYSIS
    // ============================================================================

    getTrendData() {
        if (this.scanHistory.length < 2) {
            return null;
        }

        return this.scanHistory.map(scan => ({
            timestamp: new Date(scan.timestamp).toLocaleDateString(),
            critical: scan.metrics.critical,
            high: scan.metrics.high,
            medium: scan.metrics.medium,
            securityDebt: scan.securityDebtScore
        }));
    }

    compareToPrevious(currentAnalysis) {
        const previous = this.getPreviousScan();
        if (!previous) {
            return null;
        }

        return {
            criticalDelta: currentAnalysis.metrics.critical - previous.metrics.critical,
            highDelta: currentAnalysis.metrics.high - previous.metrics.high,
            debtDelta: currentAnalysis.securityDebtScore - previous.securityDebtScore,
            trend: this.calculateTrend(currentAnalysis, previous)
        };
    }

    calculateTrend(current, previous) {
        const currentScore =
            (current.metrics.critical * 100) +
            (current.metrics.high * 20) +
            current.securityDebtScore;

        const previousScore =
            (previous.metrics.critical * 100) +
            (previous.metrics.high * 20) +
            previous.securityDebtScore;

        if (currentScore > previousScore * 1.1) return 'worsening';
        if (currentScore < previousScore * 0.9) return 'improving';
        return 'stable';
    }

    // ============================================================================
    // SETTINGS PERSISTENCE
    // ============================================================================

    loadSettings() {
        try {
            const saved = localStorage.getItem('sabha_settings');
            return saved ? JSON.parse(saved) : this.getDefaultSettings();
        } catch (e) {
            return this.getDefaultSettings();
        }
    }

    getDefaultSettings() {
        return {
            theme: 'light',
            autoSave: true,
            showTrends: true,
            defaultView: 'dashboard'
        };
    }

    saveSettings(settings) {
        this.settings = { ...this.settings, ...settings };
        localStorage.setItem('sabha_settings', JSON.stringify(this.settings));
    }

    getSettings() {
        return this.settings;
    }

    // ============================================================================
    // EXPORT / IMPORT
    // ============================================================================

    exportAll() {
        return {
            version: '1.0',
            exportDate: new Date().toISOString(),
            scanHistory: this.scanHistory,
            settings: this.settings,
            notificationConfig: JSON.parse(localStorage.getItem('sabha_notifications_config') || '{}')
        };
    }

    importAll(data) {
        try {
            if (data.scanHistory) {
                this.scanHistory = data.scanHistory;
                this.saveScanHistory();
            }
            if (data.settings) {
                this.saveSettings(data.settings);
            }
            if (data.notificationConfig) {
                localStorage.setItem('sabha_notifications_config', JSON.stringify(data.notificationConfig));
            }
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // ============================================================================
    // STATISTICS
    // ============================================================================

    getStatistics() {
        if (this.scanHistory.length === 0) {
            return null;
        }

        const total = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        this.scanHistory.forEach(scan => {
            total.critical += scan.metrics.critical;
            total.high += scan.metrics.high;
            total.medium += scan.metrics.medium;
            total.low += scan.metrics.low;
        });

        const avg = {
            critical: Math.round(total.critical / this.scanHistory.length),
            high: Math.round(total.high / this.scanHistory.length),
            medium: Math.round(total.medium / this.scanHistory.length),
            low: Math.round(total.low / this.scanHistory.length)
        };

        return {
            totalScans: this.scanHistory.length,
            averages: avg,
            totals: total,
            latestScan: this.getLatestScan()
        };
    }
}

// Export for use in main app
if (typeof window !== 'undefined') {
    window.StorageManager = StorageManager;
}
