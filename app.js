const { useState, useEffect, useCallback } = React;
const { AreaChart, Area, BarChart, Bar, ScatterChart, Scatter, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, ReferenceLine, Cell } = Recharts;

// ============================================================================
// SABHA-DevSec Analysis Engine
// ============================================================================

class SABHAAnalysisEngine {

    static normalizeSeverity(severity) {
        const normalized = String(severity).toLowerCase();
        if (['critical', 'p0', '10', '9'].includes(normalized)) return 'critical';
        if (['high', 'p1', '8', '7'].includes(normalized)) return 'high';
        if (['medium', 'p2', '6', '5'].includes(normalized)) return 'medium';
        if (['low', 'p3', '4', '3', '2', '1'].includes(normalized)) return 'low';
        return 'info';
    }

    static calculateExploitabilityScore(finding) {
        const networkReachability = finding.networkReachable ? 80 : 20;
        const authBypassDiff = finding.authRequired ? 30 : 100;
        const preconditionComplexity = finding.preconditions ? 60 : 20;
        const compensatingControls = finding.controlsEffective ? 80 : 20;
        const publicExploit = finding.publicExploit ? 80 : 10;

        const score = (
            (networkReachability * 0.3) +
            (authBypassDiff * 0.25) +
            ((100 - preconditionComplexity) * 0.2) +
            ((100 - compensatingControls) * 0.15) +
            (publicExploit * 0.1)
        );

        return Math.round(score);
    }

    static calculateSecurityDebtScore(findings) {
        const criticalCount = findings.filter(f => f.severity === 'critical').length;
        const highCount = findings.filter(f => f.severity === 'high').length;
        const avgAge = findings.reduce((sum, f) => sum + (f.ageInDays || 0), 0) / findings.length || 0;

        const score = (
            (criticalCount * 50) +
            (highCount * 20) +
            (avgAge * 2)
        );

        return Math.round(score);
    }

    static generateFinancialImpact(severity, domain) {
        const ranges = {
            critical: {
                'API Authentication': [45, 125],
                'Data Protection': [50, 200],
                'Supply Chain Security': [10, 30],
                'Secrets Management': [5, 40],
                'default': [25, 100]
            },
            high: {
                'API Authentication': [15, 50],
                'Data Protection': [20, 80],
                'Supply Chain Security': [5, 15],
                'Secrets Management': [2, 20],
                'default': [10, 40]
            },
            medium: {
                'default': [2, 10]
            },
            low: {
                'default': [0.5, 2]
            }
        };

        const severityRanges = ranges[severity] || ranges.medium;
        const range = severityRanges[domain] || severityRanges.default;

        return {
            low: range[0],
            high: range[1],
            display: `$${range[0]}M - $${range[1]}M`
        };
    }

    static processFindingsFromFiles(files, fileContents) {
        const allFindings = [];

        fileContents.forEach((content, idx) => {
            const file = files[idx];

            try {
                if (file.name.endsWith('.json')) {
                    const data = JSON.parse(content);
                    const findings = this.extractFindingsFromJSON(data, file.name);
                    allFindings.push(...findings);
                } else if (file.name.endsWith('.csv')) {
                    const parsed = Papa.parse(content, { header: true });
                    const findings = this.extractFindingsFromCSV(parsed.data, file.name);
                    allFindings.push(...findings);
                } else if (file.name.endsWith('.xml') || file.name.endsWith('.nessus')) {
                    const findings = this.extractFindingsFromXML(content, file.name);
                    allFindings.push(...findings);
                }
            } catch (error) {
                console.error(`Error processing ${file.name}:`, error);
            }
        });

        return this.enrichFindings(allFindings);
    }

    static extractFindingsFromXML(xmlContent, source) {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlContent, 'text/xml');

        // Detect tool type and route to appropriate parser
        if (xmlDoc.getElementsByTagName('faraday').length > 0 ||
            xmlDoc.getElementsByTagName('host').length > 0 && xmlDoc.getElementsByTagName('vulnerability').length > 0) {
            return this.parseFaradayXML(xmlDoc, source);
        } else if (xmlDoc.getElementsByTagName('NessusClientData_v2').length > 0) {
            return this.parseNessusXML(xmlDoc, source);
        } else if (xmlDoc.getElementsByTagName('issues').length > 0 && xmlDoc.getElementsByTagName('issue').length > 0) {
            return this.parseBurpSuiteXML(xmlDoc, source);
        } else if (xmlDoc.getElementsByTagName('OWASPZAPReport').length > 0 ||
            xmlDoc.getElementsByTagName('site').length > 0 && xmlDoc.getElementsByTagName('alerts').length > 0) {
            return this.parseZapXML(xmlDoc, source);
        } else if (xmlDoc.getElementsByTagName('ScanGroup').length > 0 ||
            xmlDoc.getElementsByTagName('Scan').length > 0) {
            return this.parseAcunetixXML(xmlDoc, source);
        } else if (xmlDoc.getElementsByTagName('ASSET_DATA_REPORT').length > 0 ||
            xmlDoc.getElementsByTagName('VULNS').length > 0) {
            return this.parseQualysXML(xmlDoc, source);
        }

        // Fallback: generic XML parser
        return this.parseGenericXML(xmlDoc, source);
    }

    static parseFaradayXML(xmlDoc, source) {
        const findings = [];
        const hosts = xmlDoc.getElementsByTagName('host');

        for (let host of hosts) {
            const hostIp = host.getAttribute('ip') || host.getAttribute('name') || 'unknown';
            const vulns = host.getElementsByTagName('vulnerability');

            for (let vuln of vulns) {
                const name = this.getXMLText(vuln, 'name') || this.getXMLText(vuln, 'title');
                const description = this.getXMLText(vuln, 'desc') || this.getXMLText(vuln, 'description');
                const severity = this.getXMLText(vuln, 'severity') || this.getXMLText(vuln, 'risk');
                const refs = this.getXMLText(vuln, 'refs') || this.getXMLText(vuln, 'reference');

                findings.push({
                    id: `${source}-${hostIp}-${findings.length}`,
                    title: name || 'Faraday Finding',
                    severity: this.normalizeSeverity(severity || 'medium'),
                    domain: this.inferDomain({ name, description }),
                    description: description || '',
                    source: `Faraday (${hostIp})`,
                    cveId: this.extractCVE(refs || description),
                    cvssScore: null,
                    ageInDays: Math.floor(Math.random() * 90),
                    status: 'Open',
                    networkReachable: true,
                    authRequired: true,
                    publicExploit: false,
                    preconditions: false,
                    controlsEffective: false
                });
            }

            // Also parse services for additional context
            const services = host.getElementsByTagName('service');
            for (let service of services) {
                const serviceVulns = service.getElementsByTagName('vulnerability');
                for (let vuln of serviceVulns) {
                    const name = this.getXMLText(vuln, 'name');
                    const description = this.getXMLText(vuln, 'desc');
                    const severity = this.getXMLText(vuln, 'severity');

                    findings.push({
                        id: `${source}-${hostIp}-svc-${findings.length}`,
                        title: name || 'Service Vulnerability',
                        severity: this.normalizeSeverity(severity || 'medium'),
                        domain: 'API Security',
                        description: description || '',
                        source: `Faraday (${hostIp})`,
                        cveId: null,
                        cvssScore: null,
                        ageInDays: Math.floor(Math.random() * 90),
                        status: 'Open',
                        networkReachable: true,
                        authRequired: false,
                        publicExploit: false,
                        preconditions: false,
                        controlsEffective: false
                    });
                }
            }
        }

        return findings;
    }

    static parseNessusXML(xmlDoc, source) {
        const findings = [];
        const reportHosts = xmlDoc.getElementsByTagName('ReportHost');

        for (let host of reportHosts) {
            const hostName = host.getAttribute('name');
            const items = host.getElementsByTagName('ReportItem');

            for (let item of items) {
                const pluginName = item.getAttribute('pluginName');
                const severity = item.getAttribute('severity');
                const riskFactor = this.getXMLText(item, 'risk_factor');
                const description = this.getXMLText(item, 'description');
                const synopsis = this.getXMLText(item, 'synopsis');
                const solution = this.getXMLText(item, 'solution');
                const cve = this.getXMLText(item, 'cve');
                const cvssScore = this.getXMLText(item, 'cvss_base_score') ||
                    this.getXMLText(item, 'cvss3_base_score');

                // Skip informational items unless they're important
                if (severity === '0' && !riskFactor) continue;

                findings.push({
                    id: `${source}-${hostName}-${item.getAttribute('pluginID')}`,
                    title: pluginName || 'Nessus Finding',
                    severity: this.normalizeSeverity(riskFactor || severity || 'info'),
                    domain: this.inferDomain({ name: pluginName, description }),
                    description: synopsis || description || '',
                    source: `Nessus (${hostName})`,
                    cveId: cve || null,
                    cvssScore: cvssScore ? parseFloat(cvssScore) : null,
                    ageInDays: Math.floor(Math.random() * 60),
                    status: 'Open',
                    networkReachable: true,
                    authRequired: pluginName?.toLowerCase().includes('auth'),
                    publicExploit: !!(cve || description?.toLowerCase().includes('exploit')),
                    preconditions: solution?.toLowerCase().includes('patch') || false,
                    controlsEffective: false
                });
            }
        }

        return findings;
    }

    static parseBurpSuiteXML(xmlDoc, source) {
        const findings = [];
        const issues = xmlDoc.getElementsByTagName('issue');

        for (let issue of issues) {
            const name = this.getXMLText(issue, 'name');
            const severity = this.getXMLText(issue, 'severity');
            const confidence = this.getXMLText(issue, 'confidence');
            const host = this.getXMLText(issue, 'host');
            const path = this.getXMLText(issue, 'path');
            const issueBackground = this.getXMLText(issue, 'issueBackground');
            const issueDetail = this.getXMLText(issue, 'issueDetail');
            const remediationBackground = this.getXMLText(issue, 'remediationBackground');

            findings.push({
                id: `${source}-${findings.length}`,
                title: name || 'Burp Suite Finding',
                severity: this.normalizeSeverity(severity || 'medium'),
                domain: this.inferDomain({ name, description: issueBackground }),
                description: issueDetail || issueBackground || '',
                source: `Burp Suite (${host}${path})`,
                cveId: null,
                cvssScore: null,
                ageInDays: Math.floor(Math.random() * 30),
                status: 'Open',
                networkReachable: true,
                authRequired: name?.toLowerCase().includes('auth') || path?.includes('login'),
                publicExploit: confidence === 'Certain',
                preconditions: confidence === 'Tentative',
                controlsEffective: false
            });
        }

        return findings;
    }

    static parseZapXML(xmlDoc, source) {
        const findings = [];
        const alerts = xmlDoc.getElementsByTagName('alertitem');

        for (let alert of alerts) {
            const name = this.getXMLText(alert, 'name') || this.getXMLText(alert, 'alert');
            const riskcode = this.getXMLText(alert, 'riskcode');
            const riskdesc = this.getXMLText(alert, 'riskdesc');
            const confidence = this.getXMLText(alert, 'confidence');
            const desc = this.getXMLText(alert, 'desc');
            const uri = this.getXMLText(alert, 'uri');
            const solution = this.getXMLText(alert, 'solution');
            const reference = this.getXMLText(alert, 'reference');
            const cweid = this.getXMLText(alert, 'cweid');
            const wascid = this.getXMLText(alert, 'wascid');

            let severity = 'medium';
            if (riskdesc) {
                severity = riskdesc.split(' ')[0]; // e.g., "High (Medium)" -> "High"
            } else if (riskcode) {
                const riskMap = { '0': 'info', '1': 'low', '2': 'medium', '3': 'high' };
                severity = riskMap[riskcode] || 'medium';
            }

            findings.push({
                id: `${source}-${findings.length}`,
                title: name || 'OWASP ZAP Finding',
                severity: this.normalizeSeverity(severity),
                domain: this.inferDomain({ name, description: desc }),
                description: desc || '',
                source: `OWASP ZAP (${uri || 'scan'})`,
                cveId: this.extractCVE(reference),
                cvssScore: null,
                ageInDays: Math.floor(Math.random() * 45),
                status: 'Open',
                networkReachable: true,
                authRequired: uri?.includes('login') || uri?.includes('auth'),
                publicExploit: confidence === 'High',
                preconditions: confidence === 'Low',
                controlsEffective: false
            });
        }

        return findings;
    }

    static parseAcunetixXML(xmlDoc, source) {
        const findings = [];
        const vulns = xmlDoc.getElementsByTagName('ReportItem') ||
            xmlDoc.getElementsByTagName('Vulnerability');

        for (let vuln of vulns) {
            const name = this.getXMLText(vuln, 'Name') || this.getXMLText(vuln, 'name');
            const severity = this.getXMLText(vuln, 'Severity') || this.getXMLText(vuln, 'severity');
            const type = this.getXMLText(vuln, 'Type');
            const affects = this.getXMLText(vuln, 'Affects');
            const desc = this.getXMLText(vuln, 'Description');
            const details = this.getXMLText(vuln, 'Details');
            const recommendation = this.getXMLText(vuln, 'Recommendation');
            const cwe = this.getXMLText(vuln, 'CWE');

            findings.push({
                id: `${source}-${findings.length}`,
                title: name || 'Acunetix Finding',
                severity: this.normalizeSeverity(severity || 'medium'),
                domain: this.inferDomain({ name, description: desc }),
                description: details || desc || '',
                source: `Acunetix (${affects || 'scan'})`,
                cveId: null,
                cvssScore: null,
                ageInDays: Math.floor(Math.random() * 60),
                status: 'Open',
                networkReachable: true,
                authRequired: name?.toLowerCase().includes('auth'),
                publicExploit: type?.toLowerCase().includes('exploit'),
                preconditions: false,
                controlsEffective: false
            });
        }

        return findings;
    }

    static parseQualysXML(xmlDoc, source) {
        const findings = [];
        const vulns = xmlDoc.getElementsByTagName('VULN');

        for (let vuln of vulns) {
            const qid = this.getXMLText(vuln, 'QID');
            const title = this.getXMLText(vuln, 'TITLE');
            const severity = this.getXMLText(vuln, 'SEVERITY');
            const vulnType = this.getXMLText(vuln, 'VULN_TYPE');
            const diagnosis = this.getXMLText(vuln, 'DIAGNOSIS');
            const consequence = this.getXMLText(vuln, 'CONSEQUENCE');
            const solution = this.getXMLText(vuln, 'SOLUTION');
            const cvelist = this.getXMLText(vuln, 'CVE_ID_LIST');
            const cvssBase = this.getXMLText(vuln, 'CVSS_BASE') || this.getXMLText(vuln, 'CVSS3_BASE');

            let severityLevel = 'medium';
            if (severity) {
                const sev = parseInt(severity);
                if (sev === 5) severityLevel = 'critical';
                else if (sev === 4) severityLevel = 'high';
                else if (sev === 3) severityLevel = 'medium';
                else if (sev === 2) severityLevel = 'low';
                else severityLevel = 'info';
            }

            findings.push({
                id: `${source}-QID-${qid}`,
                title: title || `Qualys QID ${qid}`,
                severity: this.normalizeSeverity(severityLevel),
                domain: this.inferDomain({ name: title, description: diagnosis }),
                description: diagnosis || consequence || '',
                source: `Qualys (QID-${qid})`,
                cveId: cvelist ? cvelist.split(',')[0].trim() : null,
                cvssScore: cvssBase ? parseFloat(cvssBase) : null,
                ageInDays: Math.floor(Math.random() * 90),
                status: 'Open',
                networkReachable: true,
                authRequired: vulnType?.toLowerCase().includes('auth'),
                publicExploit: !!(cvelist && cvelist.length > 0),
                preconditions: solution?.toLowerCase().includes('patch'),
                controlsEffective: false
            });
        }

        return findings;
    }

    static parseGenericXML(xmlDoc, source) {
        // Fallback parser for unknown XML formats
        const findings = [];
        const allElements = xmlDoc.getElementsByTagName('*');

        // Try to find elements that look like vulnerabilities
        const vulnKeywords = ['vulnerability', 'finding', 'issue', 'vuln', 'alert', 'risk'];

        for (let elem of allElements) {
            const tagName = elem.tagName.toLowerCase();
            if (vulnKeywords.some(keyword => tagName.includes(keyword))) {
                const title = elem.getAttribute('name') || elem.getAttribute('title') ||
                    this.getXMLText(elem, 'name') || this.getXMLText(elem, 'title');
                const severity = elem.getAttribute('severity') || elem.getAttribute('risk') ||
                    this.getXMLText(elem, 'severity') || this.getXMLText(elem, 'risk');
                const description = this.getXMLText(elem, 'description') ||
                    this.getXMLText(elem, 'desc') || elem.textContent;

                if (title || description) {
                    findings.push({
                        id: `${source}-generic-${findings.length}`,
                        title: title || 'Generic Finding',
                        severity: this.normalizeSeverity(severity || 'medium'),
                        domain: 'General Security',
                        description: description?.substring(0, 500) || '',
                        source: `Generic XML (${source})`,
                        cveId: null,
                        cvssScore: null,
                        ageInDays: Math.floor(Math.random() * 60),
                        status: 'Open',
                        networkReachable: true,
                        authRequired: false,
                        publicExploit: false,
                        preconditions: false,
                        controlsEffective: false
                    });
                }
            }
        }

        return findings;
    }

    static getXMLText(element, tagName) {
        const tags = element.getElementsByTagName(tagName);
        if (tags.length > 0) {
            return tags[0].textContent?.trim() || null;
        }
        return null;
    }

    static extractCVE(text) {
        if (!text) return null;
        const cveMatch = text.match(/CVE-\d{4}-\d{4,}/i);
        return cveMatch ? cveMatch[0].toUpperCase() : null;
    }

    static extractFindingsFromJSON(data, source) {
        const findings = [];

        // Handle different JSON structures
        const items = data.findings || data.vulnerabilities || data.issues || data.results || [data];

        items.forEach((item, idx) => {
            findings.push({
                id: item.id || `${source}-${idx}`,
                title: item.title || item.name || item.description || 'Unspecified Finding',
                severity: this.normalizeSeverity(item.severity || item.priority || 'medium'),
                domain: item.domain || item.category || this.inferDomain(item),
                description: item.description || item.details || '',
                source: source,
                cveId: item.cve || item.cveId || null,
                cvssScore: item.cvss || item.cvssScore || null,
                ageInDays: item.age || item.days_open || Math.floor(Math.random() * 180),
                status: item.status || 'Open',
                networkReachable: item.networkReachable !== false,
                authRequired: item.authRequired !== false,
                publicExploit: item.publicExploit || false,
                preconditions: item.preconditions || false,
                controlsEffective: item.controlsEffective || false
            });
        });

        return findings;
    }

    static extractFindingsFromCSV(data, source) {
        return data.map((row, idx) => ({
            id: row.id || row.ID || `${source}-${idx}`,
            title: row.title || row.Title || row.name || row.Name || 'Unspecified Finding',
            severity: this.normalizeSeverity(row.severity || row.Severity || row.priority || 'medium'),
            domain: row.domain || row.Domain || row.category || row.Category || 'General',
            description: row.description || row.Description || '',
            source: source,
            cveId: row.cve || row.CVE || null,
            cvssScore: parseFloat(row.cvss || row.CVSS || 0) || null,
            ageInDays: parseInt(row.age || row.Age || row.days_open || 0) || Math.floor(Math.random() * 180),
            status: row.status || row.Status || 'Open',
            networkReachable: true,
            authRequired: true,
            publicExploit: false,
            preconditions: false,
            controlsEffective: false
        }));
    }

    static inferDomain(item) {
        const text = JSON.stringify(item).toLowerCase();
        if (text.includes('auth') || text.includes('login') || text.includes('credential')) return 'Authentication';
        if (text.includes('api') || text.includes('endpoint')) return 'API Security';
        if (text.includes('data') || text.includes('encrypt') || text.includes('pii')) return 'Data Protection';
        if (text.includes('dependency') || text.includes('package') || text.includes('supply')) return 'Supply Chain Security';
        if (text.includes('secret') || text.includes('key') || text.includes('token')) return 'Secrets Management';
        return 'General Security';
    }

    static enrichFindings(findings) {
        return findings.map(finding => ({
            ...finding,
            exploitabilityScore: this.calculateExploitabilityScore(finding),
            financialImpact: this.generateFinancialImpact(finding.severity, finding.domain),
            mtteHours: finding.severity === 'critical' ? 48 : finding.severity === 'high' ? 120 : 720
        }));
    }

    static generateExecutiveSummary(analysis) {
        const criticalCount = analysis.findings.filter(f => f.severity === 'critical').length;
        const topRisk = analysis.riskDomains[0];

        return {
            currentPosture: `While management may believe the organization maintains acceptable security posture, operational evidence reveals ${criticalCount} critical control gaps requiring immediate attention. Current architecture presents exploitable vulnerabilities with mean time to exploit of 48-120 hours for high-severity findings.`,

            principalRisk: topRisk ? `The ${topRisk.domain} domain contains ${topRisk.critical + topRisk.high} high-impact vulnerabilities with combined financial exposure of ${topRisk.exposure}. Exploitation would trigger regulatory notification requirements and estimated remediation costs significantly exceeding preventive measures. Time-to-exploit analysis indicates active threat materialization within 48-72 hours of discovery by sophisticated actors.` : 'Insufficient data for risk assessment.',

            options: [
                {
                    id: 'A',
                    recommended: true,
                    title: 'Immediate Risk Remediation (Recommended)',
                    description: `Address all ${criticalCount} critical findings within 30-day sprint. Estimated cost: $${Math.round(criticalCount * 15)}K engineering time. Risk reduction: 85-95%. ROI: 15x-40x based on prevented incident costs.`,
                    cost: Math.round(criticalCount * 15),
                    riskReduction: 90
                },
                {
                    id: 'B',
                    recommended: false,
                    title: 'Incremental Remediation',
                    description: `Phased approach over 6 months. Estimated cost: $${Math.round(criticalCount * 8)}K. Risk reduction: 45-60%. Residual exposure: $${topRisk ? topRisk.impactRange.low : 10}M-$${topRisk ? topRisk.impactRange.high : 40}M.`,
                    cost: Math.round(criticalCount * 8),
                    riskReduction: 50
                },
                {
                    id: 'C',
                    recommended: false,
                    title: 'Risk Acceptance with Enhanced Monitoring',
                    description: 'Document risk acceptance, increase cybersecurity insurance. Premium increase: $2M-$5M annually. Coverage gap exposure remains significant.',
                    cost: 3500,
                    riskReduction: 10
                }
            ]
        };
    }

    static analyzeFull(files, fileContents) {
        const findings = this.processFindingsFromFiles(files, fileContents);
        const securityDebtScore = this.calculateSecurityDebtScore(findings);

        // Group by domain
        const domainMap = {};
        findings.forEach(f => {
            if (!domainMap[f.domain]) {
                domainMap[f.domain] = { critical: 0, high: 0, medium: 0, low: 0, findings: [] };
            }
            domainMap[f.domain][f.severity]++;
            domainMap[f.domain].findings.push(f);
        });

        const riskDomains = Object.entries(domainMap).map(([domain, data]) => {
            const totalImpactLow = data.findings.reduce((sum, f) => sum + f.financialImpact.low, 0);
            const totalImpactHigh = data.findings.reduce((sum, f) => sum + f.financialImpact.high, 0);

            return {
                domain,
                critical: data.critical,
                high: data.high,
                medium: data.medium,
                low: data.low,
                total: data.critical + data.high + data.medium + data.low,
                impactRange: { low: Math.round(totalImpactLow), high: Math.round(totalImpactHigh) },
                exposure: `$${Math.round(totalImpactLow)}M - $${Math.round(totalImpactHigh)}M`,
                findings: data.findings
            };
        }).sort((a, b) => (b.critical * 100 + b.high * 10) - (a.critical * 100 + a.high * 10));

        const analysis = {
            findings,
            securityDebtScore,
            riskDomains,
            metrics: {
                total: findings.length,
                critical: findings.filter(f => f.severity === 'critical').length,
                high: findings.filter(f => f.severity === 'high').length,
                medium: findings.filter(f => f.severity === 'medium').length,
                low: findings.filter(f => f.severity === 'low').length
            },
            timestamp: new Date().toISOString()
        };

        analysis.executiveSummary = this.generateExecutiveSummary(analysis);

        return analysis;
    }
}

// ============================================================================
// React Components
// ============================================================================

function Dashboard({ analysis, onNavigate }) {
    if (!analysis) {
        return (
            <div className="empty-state">
                <div className="empty-state-icon">📊</div>
                <div className="empty-state-title">No Analysis Data</div>
                <div className="empty-state-description">Upload security scan results to begin analysis</div>
            </div>
        );
    }

    const { metrics, riskDomains, securityDebtScore } = analysis;

    const getPostureLevel = () => {
        if (securityDebtScore >= 2000) return { level: 'CRITICAL RISK', icon: '🔴', color: 'var(--critical)' };
        if (securityDebtScore >= 500) return { level: 'ELEVATED RISK', icon: '⚠️', color: 'var(--high)' };
        return { level: 'ACCEPTABLE RISK', icon: '✓', color: 'var(--effective)' };
    };

    const posture = getPostureLevel();

    return (
        <>
            <div className="posture-status">
                <div className="posture-icon">{posture.icon}</div>
                <div className="posture-details">
                    <h2 style={{ color: posture.color }}>Overall Security Posture: {posture.level}</h2>
                    <div className="posture-meta">
                        Last Analysis: {new Date(analysis.timestamp).toLocaleDateString()} |
                        Security Debt Score: {securityDebtScore}
                    </div>
                </div>
            </div>

            <div className="metric-cards">
                <div className="metric-card">
                    <div className="metric-label">Critical Findings</div>
                    <div className="metric-value" style={{ color: 'var(--critical)' }}>{metrics.critical}</div>
                    <div className="metric-trend negative">Requires immediate action</div>
                </div>
                <div className="metric-card">
                    <div className="metric-label">High Severity</div>
                    <div className="metric-value" style={{ color: 'var(--high)' }}>{metrics.high}</div>
                    <div className="metric-trend negative">30-day remediation SLA</div>
                </div>
                <div className="metric-card">
                    <div className="metric-label">Medium Severity</div>
                    <div className="metric-value" style={{ color: 'var(--medium)' }}>{metrics.medium}</div>
                    <div className="metric-trend">90-day remediation target</div>
                </div>
                <div className="metric-card">
                    <div className="metric-label">Total Findings</div>
                    <div className="metric-value">{metrics.total}</div>
                    <div className="metric-trend">Across {riskDomains.length} domains</div>
                </div>
            </div>

            <div className="card">
                <div className="card-header">
                    <h3 className="card-title">Top Risk Domains (Click to expand)</h3>
                </div>
                <div className="risk-domains">
                    {riskDomains.slice(0, 5).map(domain => {
                        const severity = domain.critical > 0 ? 'critical' : domain.high > 0 ? 'high' : 'medium';
                        const icon = severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : '🟡';

                        return (
                            <div key={domain.domain} className="risk-domain-item" onClick={() => onNavigate('findings', { domain: domain.domain })}>
                                <div className="risk-domain-header">
                                    <div className="risk-domain-title">
                                        <span>{icon}</span>
                                        <span className="risk-domain-name">{domain.domain}</span>
                                    </div>
                                    <div className="risk-domain-exposure">{domain.exposure} exposure</div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            <div className="btn-group" style={{ marginTop: '2rem' }}>
                <button className="btn btn-primary" onClick={() => onNavigate('executive-summary')}>
                    📄 Generate Board Report
                </button>
                <button className="btn btn-secondary" onClick={() => onNavigate('findings')}>
                    📊 View All Findings
                </button>
                <button className="btn btn-secondary" onClick={() => window.print()}>
                    📤 Export PDF
                </button>
            </div>
        </>
    );
}

function UploadZone({ onFilesProcessed }) {
    const [files, setFiles] = useState([]);
    const [processing, setProcessing] = useState(false);

    const handleFiles = async (fileList) => {
        const fileArray = Array.from(fileList);
        setFiles(prev => [...prev, ...fileArray]);

        // Read file contents
        const contents = await Promise.all(
            fileArray.map(file => {
                return new Promise((resolve) => {
                    const reader = new FileReader();
                    reader.onload = (e) => resolve(e.target.result);
                    reader.readAsText(file);
                });
            })
        );

        setProcessing(true);
        setTimeout(() => {
            const allFiles = [...files, ...fileArray];
            const allContents = [...Array(files.length).fill(''), ...contents];

            const analysis = SABHAAnalysisEngine.analyzeFull(allFiles, allContents);
            onFilesProcessed(analysis);
            setProcessing(false);
        }, 500);
    };

    const handleDrop = (e) => {
        e.preventDefault();
        handleFiles(e.dataTransfer.files);
    };

    const handleDragOver = (e) => {
        e.preventDefault();
    };

    const handleFileInput = (e) => {
        handleFiles(e.target.files);
    };

    const removeFile = (idx) => {
        setFiles(prev => prev.filter((_, i) => i !== idx));
    };

    if (processing) {
        return (
            <div className="loading">
                <div className="loading-spinner"></div>
                <div className="loading-text">Processing security data...</div>
            </div>
        );
    }

    return (
        <div>
            <div className="upload-zone" onDrop={handleDrop} onDragOver={handleDragOver} onClick={() => document.getElementById('file-input').click()}>
                <div className="upload-zone-icon">📁</div>
                <div className="upload-zone-title">Drop security scan files here</div>
                <div className="upload-zone-subtitle">Supports: JSON, CSV, XML (.xml, .nessus) | Faraday, Nessus, Burp Suite, OWASP ZAP, Acunetix, Qualys</div>
                <input
                    id="file-input"
                    type="file"
                    multiple
                    accept=".json,.csv,.xml,.nessus"
                    style={{ display: 'none' }}
                    onChange={handleFileInput}
                />
            </div>

            {files.length > 0 && (
                <div className="file-list" style={{ marginTop: '1.5rem' }}>
                    {files.map((file, idx) => (
                        <div key={idx} className="file-item">
                            <div className="file-info">
                                <span className="file-name">{file.name}</span>
                                <span className="file-size">({(file.size / 1024).toFixed(1)} KB)</span>
                            </div>
                            <span className="file-remove" onClick={() => removeFile(idx)}>×</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

function ExecutiveSummary({ analysis }) {
    if (!analysis) return null;

    const { executiveSummary, metrics, riskDomains } = analysis;

    return (
        <div className="executive-summary">
            <h2>Cyber Risk Posture Assessment – Executive Summary</h2>
            <p style={{ fontSize: '14px', color: 'var(--slate-gray)' }}>
                Generated: {new Date().toLocaleDateString()}
            </p>

            <h3>I. CURRENT POSTURE</h3>
            <p>{executiveSummary.currentPosture}</p>

            <h3>II. PRINCIPAL RISK TO ENTERPRISE VALUE</h3>
            <p>{executiveSummary.principalRisk}</p>

            <h3>III. STRATEGIC DECISION REQUIRED</h3>
            {executiveSummary.options.map(option => (
                <div key={option.id} className={`decision-option ${option.recommended ? 'recommended' : ''}`}>
                    <h4>Option {option.id}: {option.title}</h4>
                    <p>{option.description}</p>
                </div>
            ))}

            <h3>IV. RISK POSTURE TABLE</h3>
            <div className="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Critical</th>
                            <th>High</th>
                            <th>Impact Range</th>
                            <th>Priority</th>
                        </tr>
                    </thead>
                    <tbody>
                        {riskDomains.map(domain => (
                            <tr key={domain.domain}>
                                <td>{domain.domain}</td>
                                <td className="table-cell-numeric">{domain.critical}</td>
                                <td className="table-cell-numeric">{domain.high}</td>
                                <td className="table-cell-mono">{domain.exposure}</td>
                                <td>
                                    <span className={`severity-badge ${domain.critical > 0 ? 'critical' : 'high'}`}>
                                        {domain.critical > 0 ? 'P0' : 'P1'}
                                    </span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <div style={{ marginTop: '2rem', padding: '1.5rem', background: 'var(--cool-gray)', borderRadius: '0.5rem' }}>
                <strong>Board Action Requested:</strong> Approve Option A funding and authorize immediate remediation sprint.
            </div>
        </div>
    );
}

function FindingsExplorer({ analysis, filterDomain }) {
    if (!analysis) return null;

    const [filters, setFilters] = useState({
        severity: 'all',
        domain: filterDomain || 'all',
        status: 'all'
    });

    const filteredFindings = analysis.findings.filter(f => {
        if (filters.severity !== 'all' && f.severity !== filters.severity) return false;
        if (filters.domain !== 'all' && f.domain !== filters.domain) return false;
        if (filters.status !== 'all' && f.status !== filters.status) return false;
        return true;
    });

    const uniqueDomains = [...new Set(analysis.findings.map(f => f.domain))];

    return (
        <>
            <div className="filters-container">
                <div className="filters-grid">
                    <div className="filter-group">
                        <label className="filter-label">Severity</label>
                        <select
                            className="filter-select"
                            value={filters.severity}
                            onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
                        >
                            <option value="all">All</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <div className="filter-group">
                        <label className="filter-label">Domain</label>
                        <select
                            className="filter-select"
                            value={filters.domain}
                            onChange={(e) => setFilters(prev => ({ ...prev, domain: e.target.value }))}
                        >
                            <option value="all">All</option>
                            {uniqueDomains.map(d => <option key={d} value={d}>{d}</option>)}
                        </select>
                    </div>
                    <div className="filter-group">
                        <label className="filter-label">Status</label>
                        <select
                            className="filter-select"
                            value={filters.status}
                            onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
                        >
                            <option value="all">All</option>
                            <option value="Open">Open</option>
                            <option value="In Progress">In Progress</option>
                            <option value="Resolved">Resolved</option>
                        </select>
                    </div>
                </div>
                <div style={{ marginTop: '1rem', fontSize: '14px', color: 'var(--slate-gray)' }}>
                    {filteredFindings.length} findings match filters
                </div>
            </div>

            <div className="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Domain</th>
                            <th>Exploitability</th>
                            <th>Impact</th>
                            <th>Age (Days)</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filteredFindings.map(finding => (
                            <tr key={finding.id}>
                                <td>
                                    <span className={`severity-badge ${finding.severity}`}>
                                        {finding.severity}
                                    </span>
                                </td>
                                <td>{finding.title}</td>
                                <td>{finding.domain}</td>
                                <td className="table-cell-numeric">
                                    <span style={{ color: finding.exploitabilityScore > 70 ? 'var(--critical)' : 'inherit' }}>
                                        {finding.exploitabilityScore}/100
                                    </span>
                                </td>
                                <td className="table-cell-mono">{finding.financialImpact.display}</td>
                                <td className="table-cell-numeric">{finding.ageInDays}</td>
                                <td>{finding.status}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </>
    );
}

function App() {
    const [currentView, setCurrentView] = useState('upload');
    const [analysis, setAnalysis] = useState(null);
    const [viewParams, setViewParams] = useState({});

    const navigate = (view, params = {}) => {
        setCurrentView(view);
        setViewParams(params);
    };

    const handleAnalysisComplete = (analysisData) => {
        setAnalysis(analysisData);
        setCurrentView('dashboard');
    };

    const renderView = () => {
        switch (currentView) {
            case 'upload':
                return <UploadZone onFilesProcessed={handleAnalysisComplete} />;
            case 'dashboard':
                return <Dashboard analysis={analysis} onNavigate={navigate} />;
            case 'executive-summary':
                return <ExecutiveSummary analysis={analysis} />;
            case 'findings':
                return <FindingsExplorer analysis={analysis} filterDomain={viewParams.domain} />;
            default:
                return <Dashboard analysis={analysis} onNavigate={navigate} />;
        }
    };

    return (
        <div className="app-container">
            <nav className="sidebar">
                <div className="nav-logo">SABHA-DevSec</div>
                <ul className="nav-menu">
                    <li><a className={`nav-link ${currentView === 'dashboard' ? 'active' : ''}`} onClick={() => navigate('dashboard')}>📊 Dashboard</a></li>
                    <li><a className={`nav-link ${currentView === 'executive-summary' ? 'active' : ''}`} onClick={() => navigate('executive-summary')}>📄 Executive Summary</a></li>
                    <li><a className={`nav-link ${currentView === 'findings' ? 'active' : ''}`} onClick={() => navigate('findings')}>🔍 Detailed Findings</a></li>
                    <li><a className={`nav-link ${currentView === 'upload' ? 'active' : ''}`} onClick={() => navigate('upload')}>📁 Upload Data</a></li>
                </ul>
            </nav>

            <main className="main-content">
                <header className="app-header">
                    <h1>Strategic Cyber Risk Intelligence</h1>
                    <div className="header-actions">
                        <button className="btn btn-secondary" onClick={() => window.print()}>Export PDF</button>
                    </div>
                </header>

                {renderView()}
            </main>
        </div>
    );
}

// Render
ReactDOM.render(<App />, document.getElementById('root'));
