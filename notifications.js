// SABHA-DevSec Notification System
// Handles Slack, Teams, Email, and Generic Webhooks

class NotificationManager {
    constructor() {
        this.config = this.loadConfig();
        this.notificationLog = this.loadLog();
    }

    loadConfig() {
        try {
            const saved = localStorage.getItem('sabha_notifications_config');
            return saved ? JSON.parse(saved) : this.getDefaultConfig();
        } catch (e) {
            return this.getDefaultConfig();
        }
    }

    getDefaultConfig() {
        return {
            slack: {
                enabled: false,
                webhookUrl: '',
                channel: '#security-alerts',
                username: 'SABHA-DevSec'
            },
            teams: {
                enabled: false,
                webhookUrl: ''
            },
            email: {
                enabled: false,
                apiEndpoint: '',
                to: '',
                from: 'sabha@security.local'
            },
            webhooks: {
                enabled: false,
                urls: []
            },
            thresholds: {
                critical: 1,
                high: 5,
                securityDebtScore: 500,
                notifyOnEveryScannull: true
            },
            notifications: {
                onCriticalFindings: true,
                onHighDebtScore: true,
                onScanComplete: true,
                onTrendWorsening: true
            }
        };
    }

    saveConfig(config) {
        this.config = config;
        localStorage.setItem('sabha_notifications_config', JSON.stringify(config));
    }

    loadLog() {
        try {
            const saved = localStorage.getItem('sabha_notification_log');
            return saved ? JSON.parse(saved) : [];
        } catch (e) {
            return [];
        }
    }

    saveLog() {
        // Keep only last 100 notifications
        if (this.notificationLog.length > 100) {
            this.notificationLog = this.notificationLog.slice(-100);
        }
        localStorage.setItem('sabha_notification_log', JSON.stringify(this.notificationLog));
    }

    addToLog(entry) {
        this.notificationLog.push({
            ...entry,
            timestamp: new Date().toISOString()
        });
        this.saveLog();
    }

    // ============================================================================
    // SLACK INTEGRATION
    // ============================================================================

    async sendSlackNotification(analysis, type = 'scan_complete') {
        if (!this.config.slack.enabled || !this.config.slack.webhookUrl) {
            return { success: false, error: 'Slack not configured' };
        }

        const message = this.buildSlackMessage(analysis, type);

        try {
            const response = await fetch(this.config.slack.webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(message)
            });

            const success = response.ok;
            this.addToLog({
                channel: 'slack',
                type,
                status: success ? 'success' : 'failed',
                message: success ? 'Notification sent' : `Failed: ${response.status}`
            });

            return { success, error: success ? null : `HTTP ${response.status}` };
        } catch (error) {
            this.addToLog({
                channel: 'slack',
                type,
                status: 'error',
                message: error.message
            });
            return { success: false, error: error.message };
        }
    }

    buildSlackMessage(analysis, type) {
        const { metrics, securityDebtScore, riskDomains } = analysis;
        const topDomain = riskDomains[0];

        let color = '#10B981'; // Green
        let emoji = '✅';
        let title = 'Security Scan Complete';

        if (metrics.critical > 0) {
            color = '#DC2626';
            emoji = '🚨';
            title = 'Critical Security Findings Detected';
        } else if (securityDebtScore > this.config.thresholds.securityDebtScore) {
            color = '#EA580C';
            emoji = '⚠️';
            title = 'Elevated Security Debt Score';
        }

        return {
            username: this.config.slack.username,
            channel: this.config.slack.channel,
            attachments: [{
                color,
                blocks: [
                    {
                        type: 'header',
                        text: {
                            type: 'plain_text',
                            text: `${emoji} ${title}`
                        }
                    },
                    {
                        type: 'section',
                        fields: [
                            {
                                type: 'mrkdwn',
                                text: `*Critical:* ${metrics.critical}`
                            },
                            {
                                type: 'mrkdwn',
                                text: `*High:* ${metrics.high}`
                            },
                            {
                                type: 'mrkdwn',
                                text: `*Medium:* ${metrics.medium}`
                            },
                            {
                                type: 'mrkdwn',
                                text: `*Low:* ${metrics.low}`
                            },
                            {
                                type: 'mrkdwn',
                                text: `*Security Debt:* ${securityDebtScore}`
                            },
                            {
                                type: 'mrkdwn',
                                text: `*Total Findings:* ${metrics.total}`
                            }
                        ]
                    },
                    topDomain && {
                        type: 'section',
                        text: {
                            type: 'mrkdwn',
                            text: `*🎯 Top Risk Domain:* ${topDomain.domain}\n${topDomain.critical} critical, ${topDomain.high} high findings\nFinancial Exposure: ${topDomain.exposure}`
                        }
                    },
                    {
                        type: 'context',
                        elements: [{
                            type: 'mrkdwn',
                            text: `Scanned: ${new Date(analysis.timestamp).toLocaleString()} | Total Domains: ${riskDomains.length}`
                        }]
                    },
                    {
                        type: 'actions',
                        elements: [{
                            type: 'button',
                            text: {
                                type: 'plain_text',
                                text: '📊 View Dashboard'
                            },
                            url: window.location.origin,
                            style: metrics.critical > 0 ? 'danger' : 'primary'
                        }]
                    }
                ].filter(Boolean)
            }]
        };
    }

    // ============================================================================
    // MICROSOFT TEAMS INTEGRATION
    // ============================================================================

    async sendTeamsNotification(analysis, type = 'scan_complete') {
        if (!this.config.teams.enabled || !this.config.teams.webhookUrl) {
            return { success: false, error: 'Teams not configured' };
        }

        const card = this.buildTeamsCard(analysis, type);

        try {
            const response = await fetch(this.config.teams.webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(card)
            });

            const success = response.ok;
            this.addToLog({
                channel: 'teams',
                type,
                status: success ? 'success' : 'failed',
                message: success ? 'Notification sent' : `Failed: ${response.status}`
            });

            return { success, error: success ? null : `HTTP ${response.status}` };
        } catch (error) {
            this.addToLog({
                channel: 'teams',
                type,
                status: 'error',
                message: error.message
            });
            return { success: false, error: error.message };
        }
    }

    buildTeamsCard(analysis, type) {
        const { metrics, securityDebtScore, riskDomains } = analysis;
        const topDomain = riskDomains[0];

        let themeColor = '10B981'; // Green
        let title = '✅ Security Scan Complete';

        if (metrics.critical > 0) {
            themeColor = 'DC2626';
            title = '🚨 Critical Security Findings Detected';
        } else if (securityDebtScore > this.config.thresholds.securityDebtScore) {
            themeColor = 'EA580C';
            title = '⚠️ Elevated Security Debt Score';
        }

        const facts = [
            { name: 'Critical Findings:', value: metrics.critical.toString() },
            { name: 'High Severity:', value: metrics.high.toString() },
            { name: 'Medium Severity:', value: metrics.medium.toString() },
            { name: 'Security Debt Score:', value: securityDebtScore.toString() },
            { name: 'Total Findings:', value: metrics.total.toString() }
        ];

        if (topDomain) {
            facts.push(
                { name: 'Top Risk Domain:', value: topDomain.domain },
                { name: 'Financial Exposure:', value: topDomain.exposure }
            );
        }

        return {
            '@type': 'MessageCard',
            '@context': 'https://schema.org/extensions',
            themeColor,
            title,
            summary: `SABHA-DevSec: ${metrics.total} findings (${metrics.critical} critical)`,
            sections: [{
                activityTitle: 'Security Risk Assessment',
                activitySubtitle: new Date(analysis.timestamp).toLocaleString(),
                facts
            }],
            potentialAction: [{
                '@type': 'OpenUri',
                name: 'View Executive Report',
                targets: [{
                    os: 'default',
                    uri: window.location.origin
                }]
            }]
        };
    }

    // ============================================================================
    // GENERIC WEBHOOKS
    // ============================================================================

    async sendWebhookNotification(analysis, type = 'scan_complete') {
        if (!this.config.webhooks.enabled || this.config.webhooks.urls.length === 0) {
            return { success: false, error: 'Webhooks not configured' };
        }

        const payload = {
            event: type,
            timestamp: new Date().toISOString(),
            analysis: {
                metrics: analysis.metrics,
                securityDebtScore: analysis.securityDebtScore,
                topDomain: analysis.riskDomains[0]?.domain || null,
                findings: analysis.findings.slice(0, 10).map(f => ({
                    id: f.id,
                    title: f.title,
                    severity: f.severity,
                    domain: f.domain
                }))
            }
        };

        const results = await Promise.all(
            this.config.webhooks.urls.map(async (url) => {
                try {
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });

                    const success = response.ok;
                    this.addToLog({
                        channel: 'webhook',
                        type,
                        status: success ? 'success' : 'failed',
                        message: `${url}: ${success ? 'OK' : response.status}`
                    });

                    return { url, success };
                } catch (error) {
                    this.addToLog({
                        channel: 'webhook',
                        type,
                        status: 'error',
                        message: `${url}: ${error.message}`
                    });
                    return { url, success: false, error: error.message };
                }
            })
        );

        return {
            success: results.some(r => r.success),
            results
        };
    }

    // ============================================================================
    // NOTIFICATION ORCHESTRATION
    // ============================================================================

    async notifyAll(analysis) {
        const { metrics, securityDebtScore } = analysis;

        // Determine if we should send notifications based on thresholds
        const shouldNotify =
            (this.config.notifications.onCriticalFindings && metrics.critical >= this.config.thresholds.critical) ||
            (this.config.notifications.onHighDebtScore && securityDebtScore >= this.config.thresholds.securityDebtScore) ||
            this.config.notifications.onScanComplete;

        if (!shouldNotify) {
            return { sent: false, reason: 'Thresholds not met' };
        }

        const results = {};

        // Send to all configured channels in parallel
        if (this.config.slack.enabled) {
            results.slack = await this.sendSlackNotification(analysis);
        }

        if (this.config.teams.enabled) {
            results.teams = await this.sendTeamsNotification(analysis);
        }

        if (this.config.webhooks.enabled) {
            results.webhooks = await this.sendWebhookNotification(analysis);
        }

        return { sent: true, results };
    }

    // ============================================================================
    // TEST NOTIFICATIONS
    // ============================================================================

    async testSlack() {
        const testAnalysis = this.getTestAnalysis();
        return await this.sendSlackNotification(testAnalysis, 'test');
    }

    async testTeams() {
        const testAnalysis = this.getTestAnalysis();
        return await this.sendTeamsNotification(testAnalysis, 'test');
    }

    async testWebhook() {
        const testAnalysis = this.getTestAnalysis();
        return await this.sendWebhookNotification(testAnalysis, 'test');
    }

    getTestAnalysis() {
        return {
            metrics: {
                total: 23,
                critical: 3,
                high: 8,
                medium: 10,
                low: 2
            },
            securityDebtScore: 547,
            riskDomains: [{
                domain: 'API Authentication',
                critical: 2,
                high: 5,
                exposure: '$45M - $125M'
            }],
            timestamp: new Date().toISOString()
        };
    }

    // ============================================================================
    // NOTIFICATION LOG
    // ============================================================================

    getLog() {
        return this.notificationLog.slice().reverse(); // Most recent first
    }

    clearLog() {
        this.notificationLog = [];
        this.saveLog();
    }
}

// Export for use in main app
if (typeof window !== 'undefined') {
    window.NotificationManager = NotificationManager;
}
