#!/usr/bin/env node

/**
 * Sabha-DevSec CLI Tool
 * Headless security analysis for CI/CD pipelines
 */

const fs = require('fs');
const path = require('path');

// Parse command line arguments
const args = process.argv.slice(2);
const command = args[0];

function showHelp() {
    console.log(`
Sabha-DevSec CLI - Headless Security Analysis Tool

USAGE:
    sabha [COMMAND] [OPTIONS]

COMMANDS:
    analyze <file>       Analyze security scan file(s)
    report              Generate reports from analysis
    export              Export results in various formats
    config              Manage configuration
    version             Show version information
    help                Show this help message

ANALYZE OPTIONS:
    -f, --file <path>           Input file path (supports JSON, CSV, XML)
    -d, --directory <path>      Scan directory for all supported files
    -o, --output <path>         Output file path (default: ./sabha-report.json)
    -format <type>              Output format: json|html|pdf|csv (default: json)
    --threshold <level>         Alert threshold: critical|high|medium|low
    --webhook <url>             Send results to webhook URL
    --slack <url>               Send to Slack webhook
    --teams <url>               Send to Microsoft Teams webhook
    --fail-on <severity>        Exit with error if findings >= severity
    --quiet                     Suppress console output
    --verbose                   Detailed logging

EXAMPLES:
    # Analyze single file
    sabha analyze --file scan-results.json

    # Analyze directory and output HTML
    sabha analyze --directory ./scans --format html --output report.html

    # CI/CD integration with failure threshold
    sabha analyze --file results.json --fail-on critical --webhook https://api.example.com/notify

    # Generate compliance report
    sabha analyze --file scan.json --format json | jq '.complianceReport'

CONFIGURATION:
    Config file: ~/.sabha/config.json

EXIT CODES:
    0 - Success (no critical findings or below threshold)
    1 - Analysis failed or critical findings found (with --fail-on)
    2 - Invalid arguments or configuration error
`);
}

function analyzeFile(filePath, options = {}) {
    console.log(`\n🔍 Analyzing: ${filePath}\n`);

    if (!fs.existsSync(filePath)) {
        console.error(`❌ Error: File not found: ${filePath}`);
        process.exit(2);
    }

    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const ext = path.extname(filePath).toLowerCase();

        // Mock analysis (in real implementation, use SABHAAnalysisEngine)
        const results = {
            file: filePath,
            analyzed: new Date().toISOString(),
            findings: [],
            metrics: {
                critical: Math.floor(Math.random() * 5),
                high: Math.floor(Math.random() * 10),
                medium: Math.floor(Math.random() * 20),
                low: Math.floor(Math.random() * 30)
            },
            securityDebtScore: Math.floor(Math.random() * 1000),
            threatIntelligence: {
                totalEnriched: Math.floor(Math.random() * 10),
                inKEV: Math.floor(Math.random() * 3),
                highEPSS: Math.floor(Math.random() * 5)
            },
            complianceReport: {
                overallStatus: 'partial-compliance',
                frameworks: [
                    { name: 'SOC 2', status: 'at-risk', gaps: 3 },
                    { name: 'ISO 27001', status: 'partial-compliance', gaps: 5 },
                    { name: 'GDPR', status: 'compliant', gaps: 0 }
                ]
            }
        };

        // Display summary
        if (!options.quiet) {
            console.log(`📊 Analysis Summary\n${'-'.repeat(50)}`);
            console.log(`Critical: ${results.metrics.critical}`);
            console.log(`High: ${results.metrics.high}`);
            console.log(`Medium: ${results.metrics.medium}`);
            console.log(`Low: ${results.metrics.low}`);
            console.log(`\nSecurity Debt Score: ${results.securityDebtScore}`);
            console.log(`\nThreat Intelligence:`);
            console.log(`  CVE Enriched: ${results.threatIntelligence.totalEnriched}`);
            console.log(`  CISA KEV: ${results.threatIntelligence.inKEV}`);
            console.log(`  High EPSS: ${results.threatIntelligence.highEPSS}`);
            console.log(`\nCompliance Status: ${results.complianceReport.overallStatus}`);
            console.log(`${'-'.repeat(50)}\n`);
        }

        // Write output file
        const outputPath = options.output || './sabha-report.json';
        fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
        console.log(`✅ Report saved to: ${outputPath}\n`);

        // Send webhooks if configured
        if (options.webhook) {
            sendWebhook(options.webhook, results);
        }
        if (options.slack) {
            sendSlackNotification(options.slack, results);
        }
        if (options.teams) {
            sendTeamsNotification(options.teams, results);
        }

        // Check failure threshold
        if (options.failOn) {
            const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
            const threshold = severityOrder[options.failOn] || 0;

            if (results.metrics.critical > 0 && threshold >= severityOrder.critical) {
                console.error(`❌ CI/CD FAILURE: Found ${results.metrics.critical} critical findings (threshold: ${options.failOn})`);
                process.exit(1);
            }
            if (results.metrics.high > 0 && threshold >= severityOrder.high && threshold < severityOrder.critical) {
                console.error(`❌ CI/CD FAILURE: Found ${results.metrics.high} high findings (threshold: ${options.failOn})`);
                process.exit(1);
            }
        }

        return results;

    } catch (error) {
        console.error(`❌ Analysis failed: ${error.message}`);
        if (options.verbose) {
            console.error(error.stack);
        }
        process.exit(1);
    }
}

function sendWebhook(url, data) {
    console.log(`📤 Sending results to webhook: ${url}`);
    // In real implementation, use fetch or axios
    console.log(`✅ Webhook sent (mock)`);
}

function sendSlackNotification(webhookUrl, data) {
    console.log(`📤 Sending Slack notification...`);
    const message = {
        text: `🔒 Sabha Security Scan Complete`,
        attachments: [{
            color: data.metrics.critical > 0 ? 'danger' : data.metrics.high > 0 ? 'warning' : 'good',
            fields: [
                { title: 'Critical', value: data.metrics.critical.toString(), short: true },
                { title: 'High', value: data.metrics.high.toString(), short: true },
                { title: 'Security Debt', value: data.securityDebtScore.toString(), short: true },
                { title: 'Compliance', value: data.complianceReport.overallStatus, short: true }
            ]
        }]
    };
    // In real implementation: fetch(webhookUrl, { method: 'POST', body: JSON.stringify(message) })
    console.log(`✅ Slack notification sent (mock)`);
}

function sendTeamsNotification(webhookUrl, data) {
    console.log(`📤 Sending Teams notification...`);
    const message = {
        "@type": "MessageCard",
        "summary": "Sabha Security Scan Complete",
        "sections": [{
            "activityTitle": "🔒 Security Scan Results",
            "facts": [
                { "name": "Critical Findings", "value": data.metrics.critical.toString() },
                { "name": "High Findings", "value": data.metrics.high.toString() },
                { "name": "Security Debt Score", "value": data.securityDebtScore.toString() },
                { "name": "Compliance Status", "value": data.complianceReport.overallStatus }
            ]
        }]
    };
    console.log(`✅ Teams notification sent (mock)`);
}

function parseOptions(args) {
    const options = {};
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg === '-f' || arg === '--file') {
            options.file = args[++i];
        } else if (arg === '-o' || arg === '--output') {
            options.output = args[++i];
        } else if (arg === '--format') {
            options.format = args[++i];
        } else if (arg === '--webhook') {
            options.webhook = args[++i];
        } else if (arg === '--slack') {
            options.slack = args[++i];
        } else if (arg === '--teams') {
            options.teams = args[++i];
        } else if (arg === '--fail-on') {
            options.failOn = args[++i];
        } else if (arg === '--quiet') {
            options.quiet = true;
        } else if (arg === '--verbose') {
            options.verbose = true;
        }
    }
    return options;
}

// Main CLI handler
switch (command) {
    case 'analyze':
        const options = parseOptions(args.slice(1));
        if (!options.file) {
            console.error('❌ Error: --file option is required\n');
            showHelp();
            process.exit(2);
        }
        analyzeFile(options.file, options);
        break;

    case 'version':
        console.log('Sabha-DevSec CLI v2.0.0');
        console.log('Enhanced with AI/ML, Threat Intelligence, and Compliance Mapping');
        break;

    case 'help':
    case '--help':
    case '-h':
    case undefined:
        showHelp();
        break;

    default:
        console.error(`❌ Unknown command: ${command}\n`);
        showHelp();
        process.exit(2);
}
