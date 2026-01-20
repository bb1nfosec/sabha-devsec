// ============================================================================
// SABHA Compliance Engine - Framework Mapping & Gap Analysis
// ============================================================================

class ComplianceEngine {
    constructor() {
        this.frameworks = this.initializeFrameworks();
    }

    // ========================================================================
    // Framework Definitions
    // ========================================================================

    initializeFrameworks() {
        return {
            soc2: {
                name: 'SOC 2 Type II',
                categories: {
                    'CC6.1': {
                        name: 'Logical and Physical Access Controls',
                        description: 'The entity implements logical access security software, infrastructure, and architectures.',
                        keywords: ['authentication', 'authorization', 'access control', 'mfa', 'rbac']
                    },
                    'CC6.6': {
                        name: 'Vulnerability Management',
                        description: 'The entity identifies, develops, and implements responses to risks.',
                        keywords: ['vulnerability', 'patch', 'scanning', 'remediation']
                    },
                    'CC6.7': {
                        name: 'Security Incident Management',
                        description: 'The entity identifies, reports, and acts upon security incidents.',
                        keywords: ['incident', 'response', 'detection', 'monitoring']
                    },
                    'CC6.8': {
                        name: 'Change Management',
                        description: 'The entity implements change management processes.',
                        keywords: ['change', 'deployment', 'testing', 'approval']
                    },
                    'CC7.2': {
                        name: 'System Monitoring',
                        description: 'The entity monitors system components and operations for anomalies.',
                        keywords: ['monitoring', 'logging', 'alerting', 'siem']
                    }
                }
            },

            iso27001: {
                name: 'ISO 27001:2013',
                categories: {
                    'A.9': {
                        name: 'Access Control',
                        description: 'To limit access to information and information processing facilities.',
                        keywords: ['access', 'authentication', 'authorization', 'privilege']
                    },
                    'A.12': {
                        name: 'Operations Security',
                        description: 'To ensure correct and secure operations of information processing facilities.',
                        keywords: ['vulnerability', 'patch', 'malware', 'backup', 'logging']
                    },
                    'A.13': {
                        name: 'Communications Security',
                        description: 'To ensure the protection of information in networks and its supporting information processing facilities.',
                        keywords: ['network', 'encryption', 'tls', 'ssl', 'transfer']
                    },
                    'A.14': {
                        name: 'System Acquisition, Development and Maintenance',
                        description: 'To ensure that information security is an integral part of information systems.',
                        keywords: ['development', 'testing', 'secure coding', 'vulnerability', 'security requirements']
                    },
                    'A.18': {
                        name: 'Compliance',
                        description: 'To avoid breaches of legal, statutory, regulatory or contractual obligations.',
                        keywords: ['audit', 'compliance', 'policy', 'review']
                    }
                }
            },

            gdpr: {
                name: 'GDPR',
                categories: {
                    'Art32': {
                        name: 'Article 32 - Security of Processing',
                        description: 'Implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk.',
                        keywords: ['encryption', 'pseudonymisation', 'confidentiality', 'integrity', 'availability', 'resilience']
                    },
                    'Art25': {
                        name: 'Article 25 - Data Protection by Design and by Default',
                        description: 'Implement appropriate technical and organizational measures for data protection.',
                        keywords: ['privacy', 'data minimization', 'protection', 'design', 'default']
                    },
                    'Art33': {
                        name: 'Article 33 - Notification of Personal Data Breach',
                        description: 'Notify supervisory authority of a personal data breach.',
                        keywords: ['breach', 'notification', 'incident', 'data leak']
                    }
                }
            },

            hipaa: {
                name: 'HIPAA Security Rule',
                categories: {
                    '164.308': {
                        name: 'Administrative Safeguards',
                        description: 'Security Management Process',
                        keywords: ['risk assessment', 'risk management', 'security incident', 'workforce security']
                    },
                    '164.310': {
                        name: 'Physical Safeguards',
                        description: 'Facility Access Controls',
                        keywords: ['physical access', 'workstation', 'device', 'media']
                    },
                    '164.312': {
                        name: 'Technical Safeguards',
                        description: 'Access Control, Audit Controls, Integrity, Transmission Security',
                        keywords: ['access control', 'encryption', 'audit', 'authentication', 'transmission']
                    },
                    '164.316': {
                        name: 'Policies and Procedures and Documentation Requirements',
                        description: 'Documentation and record retention',
                        keywords: ['policy', 'procedure', 'documentation', 'review']
                    }
                }
            },

            pcidss: {
                name: 'PCI DSS v4.0',
                categories: {
                    'Req1': {
                        name: 'Network Security Controls',
                        description: 'Install and maintain network security controls.',
                        keywords: ['firewall', 'network', 'segmentation', 'wireless']
                    },
                    'Req2': {
                        name: 'Secure Configurations',
                        description: 'Apply secure configurations to all system components.',
                        keywords: ['configuration', 'hardening', 'default', 'unnecessary services']
                    },
                    'Req3': {
                        name: 'Protect Stored Account Data',
                        description: 'Protect stored cardholder data.',
                        keywords: ['encryption', 'data protection', 'storage', 'key management']
                    },
                    'Req4': {
                        name: 'Protect Cardholder Data with Strong Cryptography',
                        description: 'Protect cardholder data with strong cryptography during transmission.',
                        keywords: ['encryption', 'tls', 'ssl', 'transmission', 'cryptography']
                    },
                    'Req6': {
                        name: 'Develop and Maintain Secure Systems and Software',
                        description: 'Develop and maintain secure systems and software.',
                        keywords: ['vulnerability', 'patch', 'secure development', 'testing', 'code review']
                    },
                    'Req8': {
                        name: 'Identify Users and Authenticate Access',
                        description: 'Identify users and authenticate access to system components.',
                        keywords: ['authentication', 'password', 'mfa', 'user', 'access']
                    },
                    'Req11': {
                        name: 'Test Security of Systems and Networks',
                        description: 'Regularly test security of systems and networks.',
                        keywords: ['vulnerability scan', 'penetration test', 'testing', 'monitoring']
                    }
                }
            }
        };
    }

    // ========================================================================
    // Compliance Mapping
    // ========================================================================

    mapFindingsToFrameworks(findings) {
        const mappings = {};

        for (const [frameworkId, framework] of Object.entries(this.frameworks)) {
            mappings[frameworkId] = {
                name: framework.name,
                categories: {},
                totalFindings: 0,
                criticalFindings: 0,
                coverageScore: 0
            };

            for (const [controlId, control] of Object.entries(framework.categories)) {
                const matchedFindings = this.findMatchingFindings(findings, control.keywords);

                mappings[frameworkId].categories[controlId] = {
                    name: control.name,
                    description: control.description,
                    findings: matchedFindings,
                    count: matchedFindings.length,
                    critical: matchedFindings.filter(f => f.severity === 'critical').length,
                    high: matchedFindings.filter(f => f.severity === 'high').length,
                    status: this.determineControlStatus(matchedFindings)
                };

                mappings[frameworkId].totalFindings += matchedFindings.length;
                mappings[frameworkId].criticalFindings += matchedFindings.filter(f => f.severity === 'critical').length;
            }

            // Calculate coverage score
            const totalControls = Object.keys(framework.categories).length;
            const controlsWithFindings = Object.values(mappings[frameworkId].categories).filter(c => c.count > 0).length;
            mappings[frameworkId].coverageScore = Math.round((controlsWithFindings / totalControls) * 100);
        }

        return mappings;
    }

    findMatchingFindings(findings, keywords) {
        return findings.filter(finding => {
            const text = (finding.title + ' ' + finding.description + ' ' + finding.domain).toLowerCase();
            return keywords.some(keyword => text.includes(keyword.toLowerCase()));
        });
    }

    determineControlStatus(findings) {
        if (findings.length === 0) return 'compliant';

        const critical = findings.filter(f => f.severity === 'critical').length;
        const high = findings.filter(f => f.severity === 'high').length;

        if (critical > 0) return 'non-compliant';
        if (high > 2) return 'at-risk';
        if (findings.length > 5) return 'needs-attention';

        return 'partial-compliance';
    }

    // ========================================================================
    // Gap Analysis
    // ========================================================================

    generateGapAnalysis(complianceMappings) {
        const gaps = [];

        for (const [frameworkId, framework] of Object.entries(complianceMappings)) {
            for (const [controlId, control] of Object.entries(framework.categories)) {
                if (control.status !== 'compliant') {
                    gaps.push({
                        framework: framework.name,
                        frameworkId,
                        control: control.name,
                        controlId,
                        status: control.status,
                        findingsCount: control.count,
                        criticalCount: control.critical,
                        highCount: control.high,
                        severity: this.calculateGapSeverity(control),
                        recommendations: this.generateRecommendations(control, controlId)
                    });
                }
            }
        }

        return gaps.sort((a, b) => this.getSeverityWeight(b.severity) - this.getSeverityWeight(a.severity));
    }

    calculateGapSeverity(control) {
        if (control.critical > 0) return 'critical';
        if (control.high > 2) return 'high';
        if (control.count > 5) return 'medium';
        return 'low';
    }

    getSeverityWeight(severity) {
        const weights = { critical: 4, high: 3, medium: 2, low: 1 };
        return weights[severity] || 0;
    }

    generateRecommendations(control, controlId) {
        const recommendations = [];

        // Generic recommendations based on control type
        if (controlId.includes('6.1') || controlId.includes('A.9') || controlId.includes('Req8')) {
            recommendations.push('Implement multi-factor authentication (MFA) for all user accounts');
            recommendations.push('Review and update access control policies');
            recommendations.push('Conduct access review and remove unnecessary privileges');
        }

        if (controlId.includes('6.6') || controlId.includes('A.12') || controlId.includes('Req6')) {
            recommendations.push('Establish regular vulnerability scanning schedule');
            recommendations.push('Implement automated patch management');
            recommendations.push('Define SLAs for vulnerability remediation');
        }

        if (controlId.includes('Art32') || controlId.includes('164.312') || controlId.includes('Req3') || controlId.includes('Req4')) {
            recommendations.push('Enable encryption at rest for all sensitive data');
            recommendations.push('Implement TLS 1.3 for all data in transit');
            recommendations.push('Review and update cryptographic standards');
        }

        if (controlId.includes('6.7') || controlId.includes('Art33') || controlId.includes('164.308')) {
            recommendations.push('Develop incident response plan');
            recommendations.push('Implement security monitoring and alerting');
            recommendations.push('Conduct tabletop exercises for breach scenarios');
        }

        // If no specific recommendations, add generic
        if (recommendations.length === 0) {
            recommendations.push('Address all critical and high severity findings');
            recommendations.push('Document remediation plan with timelines');
            recommendations.push('Assign ownership for each finding');
        }

        return recommendations;
    }

    // ========================================================================
    // Compliance Reports
    // ========================================================================

    generateComplianceReport(complianceMappings, gapAnalysis) {
        const report = {
            executiveSummary: this.generateExecutiveSummary(complianceMappings, gapAnalysis),
            frameworks: [],
            overallStatus: this.calculateOverallStatus(complianceMappings),
            timestamp: new Date().toISOString()
        };

        for (const [frameworkId, framework] of Object.entries(complianceMappings)) {
            report.frameworks.push({
                id: frameworkId,
                name: framework.name,
                totalControls: Object.keys(framework.categories).length,
                impactedControls: Object.values(framework.categories).filter(c => c.count > 0).length,
                compliantControls: Object.values(framework.categories).filter(c => c.status === 'compliant').length,
                criticalFindings: framework.criticalFindings,
                totalFindings: framework.totalFindings,
                coverageScore: framework.coverageScore,
                status: this.determineFrameworkStatus(framework),
                gaps: gapAnalysis.filter(g => g.frameworkId === frameworkId).length
            });
        }

        return report;
    }

    generateExecutiveSummary(complianceMappings, gapAnalysis) {
        const totalGaps = gapAnalysis.length;
        const criticalGaps = gapAnalysis.filter(g => g.severity === 'critical').length;
        const frameworks = Object.keys(complianceMappings).length;

        return {
            overview: `Compliance analysis across ${frameworks} regulatory frameworks identified ${totalGaps} control gaps, including ${criticalGaps} critical deficiencies requiring immediate remediation.`,
            impact: criticalGaps > 0
                ? `Critical compliance gaps pose significant regulatory risk. Failure to remediate may result in audit findings, regulatory sanctions, or certification delays.`
                : `No critical compliance gaps identified. Continue monitoring and maintain current security posture.`,
            priority: criticalGaps > 0 || gapAnalysis.filter(g => g.severity === 'high').length > 5
                ? 'immediate-action-required'
                : 'routine-remediation'
        };
    }

    determineFrameworkStatus(framework) {
        if (framework.criticalFindings > 0) return 'non-compliant';
        if (framework.totalFindings === 0) return 'compliant';
        if (framework.coverageScore < 50) return 'at-risk';
        return 'partial-compliance';
    }

    calculateOverallStatus(complianceMappings) {
        const statuses = Object.values(complianceMappings).map(f => this.determineFrameworkStatus(f));

        if (statuses.some(s => s === 'non-compliant')) return 'non-compliant';
        if (statuses.every(s => s === 'compliant')) return 'compliant';
        if (statuses.some(s => s === 'at-risk')) return 'at-risk';
        return 'partial-compliance';
    }

    // ========================================================================
    // Audit Evidence Generation
    // ========================================================================

    generateAuditEvidence(findings, framework) {
        // Generate evidence package for auditors
        return {
            framework: framework,
            scanDate: new Date().toISOString(),
            toolsUsed: [...new Set(findings.map(f => f.source))],
            totalVulnerabilities: findings.length,
            severityBreakdown: {
                critical: findings.filter(f => f.severity === 'critical').length,
                high: findings.filter(f => f.severity === 'high').length,
                medium: findings.filter(f => f.severity === 'medium').length,
                low: findings.filter(f => f.severity === 'low').length
            },
            remediationTimelines: this.generateRemediationTimelines(findings),
            compensatingControls: this.identifyCompensatingControls(findings)
        };
    }

    generateRemediationTimelines(findings) {
        const now = new Date();

        return {
            critical: {
                count: findings.filter(f => f.severity === 'critical').length,
                sla: '48 hours',
                dueDate: new Date(now.getTime() + 48 * 60 * 60 * 1000).toISOString()
            },
            high: {
                count: findings.filter(f => f.severity === 'high').length,
                sla: '30 days',
                dueDate: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString()
            },
            medium: {
                count: findings.filter(f => f.severity === 'medium').length,
                sla: '90 days',
                dueDate: new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000).toISOString()
            }
        };
    }

    identifyCompensatingControls(findings) {
        // Suggest compensating controls for findings that can't be immediately fixed
        return findings
            .filter(f => f.severity === 'critical' || f.severity === 'high')
            .map(f => ({
                finding: f.title,
                controls: [
                    'Deploy Web Application Firewall (WAF) rules',
                    'Implement enhanced monitoring and alerting',
                    'Restrict network access via firewall rules',
                    'Enable additional authentication requirements'
                ].slice(0, 2)
            }))
            .slice(0, 10);
    }
}

// Export for use in main application
if (typeof window !== 'undefined') {
    window.ComplianceEngine = ComplianceEngine;
}
