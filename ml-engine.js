// ============================================================================
// SABHA ML Engine - Advanced Vulnerability Prioritization & Risk Analysis
// ============================================================================

class MLEngine {
    constructor() {
        this.historicalData = [];
        this.riskWeights = this.initializeRiskWeights();
    }

    // ========================================================================
    // Risk Weights Configuration
    // ========================================================================

    initializeRiskWeights() {
        return {
            // Base severity weights
            severity: {
                critical: 100,
                high: 60,
                medium: 30,
                low: 10,
                info: 2
            },

            // CVSS components
            cvssBase: 8,
            cvssExploitability: 12,
            cvssImpact: 10,

            // Exploitability factors
            networkReachable: 20,
            authenticationRequired: -15,
            publicExploit: 35,
            exploitMaturity: 25,

            // Business impact
            dataExposure: 40,
            systemCriticality: 30,
            userImpact: 25,

            // Temporal factors
            ageInDays: 0.5,
            patched: -50,
            mitigationAvailable: -20,

            // Intelligence factors
            epssScore: 80,
            inKEV: 100,
            threatActorInterest: 45
        };
    }

    // ========================================================================
    // Advanced Risk Scoring Algorithm
    // ========================================================================

    calculateAdvancedRiskScore(finding) {
        let score = 0;
        const w = this.riskWeights;

        // 1. Base Severity
        score += w.severity[finding.severity] || w.severity.medium;

        // 2. CVSS Scoring
        if (finding.cvssV3Score || finding.cvssScore) {
            const cvss = finding.cvssV3Score || finding.cvssScore;
            score += cvss * w.cvssBase;

            // Parse CVSS vector for exploitability
            if (finding.cvssV3Vector) {
                const exploitability = this.parseCVSSExploitability(finding.cvssV3Vector);
                score += exploitability * w.cvssExploitability;
            }
        }

        // 3. Exploitability Factors
        if (finding.networkReachable) score += w.networkReachable;
        if (finding.authRequired) score += w.authenticationRequired;
        if (finding.publicExploit) score += w.publicExploit;

        // 4. Threat Intelligence
        if (finding.epssScore) {
            score += parseFloat(finding.epssScore) * 100 * (w.epssScore / 10);
        }
        if (finding.inKEV) score += w.inKEV;

        // 5. Temporal Factors
        if (finding.ageInDays) {
            // Older vulnerabilities = higher priority
            score += Math.min(finding.ageInDays * w.ageInDays, 100);
        }

        // 6. Business Context
        if (finding.domain) {
            const businessImpact = this.estimateBusinessImpact(finding.domain);
            score += businessImpact;
        }

        // 7. Attack Path Complexity
        const pathComplexity = this.estimateAttackPathComplexity(finding);
        score += pathComplexity;

        return Math.round(Math.max(0, Math.min(1000, score)));
    }

    parseCVSSExploitability(vectorString) {
        // Parse CVSS v3 vector for exploitability metrics
        // Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

        let exploitability = 0;

        // Attack Vector (AV)
        if (vectorString.includes('AV:N')) exploitability += 10; // Network
        else if (vectorString.includes('AV:A')) exploitability += 7; // Adjacent
        else if (vectorString.includes('AV:L')) exploitability += 4; // Local
        else if (vectorString.includes('AV:P')) exploitability += 1; // Physical

        // Attack Complexity (AC)
        if (vectorString.includes('AC:L')) exploitability += 8; // Low
        else if (vectorString.includes('AC:H')) exploitability += 3; // High

        // Privileges Required (PR)
        if (vectorString.includes('PR:N')) exploitability += 10; // None
        else if (vectorString.includes('PR:L')) exploitability += 5; // Low
        else if (vectorString.includes('PR:H')) exploitability += 2; // High

        // User Interaction (UI)
        if (vectorString.includes('UI:N')) exploitability += 8; // None
        else if (vectorString.includes('UI:R')) exploitability += 3; // Required

        return exploitability;
    }

    estimateBusinessImpact(domain) {
        const impactMap = {
            'Authentication': 90,
            'API Security': 85,
            'Data Protection': 95,
            'Supply Chain Security': 80,
            'Secrets Management': 100,
            'Session Management': 70,
            'Input Validation': 60,
            'Configuration': 50,
            'Logging': 30,
            'General Security': 40
        };

        return impactMap[domain] || 50;
    }

    estimateAttackPathComplexity(finding) {
        // Estimate how many steps needed to exploit
        let complexity = 0;

        // Direct network access
        if (finding.networkReachable) complexity -= 30;

        // Authentication barrier
        if (finding.authRequired) complexity += 20;

        // Preconditions
        if (finding.preconditions) complexity += 15;

        // Compensating controls
        if (finding.controlsEffective) complexity += 25;

        // Inverse complexity = higher score for easier exploits
        return Math.max(0, 30 - complexity);
    }

    // ========================================================================
    // Attack Path Analysis
    // ========================================================================

    generateAttackGraph(findings) {
        // Build attack graph showing relationships between vulnerabilities
        const graph = {
            nodes: [],
            edges: [],
            criticalPaths: []
        };

        // Create nodes for each finding
        findings.forEach((finding, idx) => {
            graph.nodes.push({
                id: idx,
                label: finding.title,
                severity: finding.severity,
                domain: finding.domain,
                riskScore: finding.riskScore || 0,
                type: this.classifyVulnerabilityType(finding)
            });
        });

        // Create edges based on attack chain possibilities
        for (let i = 0; i < findings.length; i++) {
            for (let j = 0; j < findings.length; j++) {
                if (i !== j) {
                    const edge = this.findAttackChainLink(findings[i], findings[j]);
                    if (edge) {
                        graph.edges.push({
                            source: i,
                            target: j,
                            ...edge
                        });
                    }
                }
            }
        }

        // Find critical paths (shortest paths to high-value targets)
        graph.criticalPaths = this.findCriticalAttackPaths(graph, findings);

        return graph;
    }

    classifyVulnerabilityType(finding) {
        const text = (finding.title + ' ' + finding.description).toLowerCase();

        if (text.match(/auth|login|credential/)) return 'initial-access';
        if (text.match(/privilege|escalat|sudo/)) return 'privilege-escalation';
        if (text.match(/lateral|spread|pivot/)) return 'lateral-movement';
        if (text.match(/data|exfil|leak/)) return 'exfiltration';
        if (text.match(/persist|backdoor|rootkit/)) return 'persistence';

        return 'general';
    }

    findAttackChainLink(source, target) {
        // Determine if source can lead to target in an attack chain
        const sourceType = this.classifyVulnerabilityType(source);
        const targetType = this.classifyVulnerabilityType(target);

        // Define logical attack progressions
        const chains = {
            'initial-access': ['privilege-escalation', 'lateral-movement', 'persistence'],
            'privilege-escalation': ['lateral-movement', 'persistence', 'exfiltration'],
            'lateral-movement': ['privilege-escalation', 'exfiltration', 'persistence'],
            'persistence': ['exfiltration', 'lateral-movement']
        };

        if (chains[sourceType]?.includes(targetType)) {
            return {
                type: 'attack-chain',
                weight: this.calculateChainWeight(source, target),
                description: `${sourceType} → ${targetType}`
            };
        }

        // Also link vulnerabilities in the same domain
        if (source.domain === target.domain) {
            return {
                type: 'same-domain',
                weight: 0.5,
                description: `Both in ${source.domain}`
            };
        }

        return null;
    }

    calculateChainWeight(source, target) {
        // Weight based on how likely this chain is
        let weight = 1.0;

        // Higher weight if both are high severity
        if (source.severity === 'critical' || source.severity === 'high') weight *= 1.5;
        if (target.severity === 'critical' || target.severity === 'high') weight *= 1.5;

        // Higher weight if source is easily exploitable
        if (source.networkReachable && !source.authRequired) weight *= 2.0;

        return weight;
    }

    findCriticalAttackPaths(graph, findings) {
        // Use modified Dijkstra's to find shortest attack paths to critical assets
        const paths = [];

        // Identify entry points (initial access vulnerabilities)
        const entryPoints = graph.nodes.filter(n => n.type === 'initial-access');

        // Identify high-value targets (critical data/privilege vulns)
        const targets = graph.nodes.filter(n =>
            (n.type === 'exfiltration' || n.type === 'privilege-escalation') &&
            (n.severity === 'critical' || n.severity === 'high')
        );

        // Find shortest paths from each entry point to each target
        entryPoints.forEach(entry => {
            targets.forEach(target => {
                const path = this.findShortestPath(graph, entry.id, target.id);
                if (path && path.length > 1) {
                    paths.push({
                        entryPoint: findings[entry.id].title,
                        target: findings[target.id].title,
                        path: path.map(id => findings[id].title),
                        length: path.length,
                        totalRisk: path.reduce((sum, id) => sum + (findings[id].riskScore || 0), 0)
                    });
                }
            });
        });

        // Sort by total risk
        return paths.sort((a, b) => b.totalRisk - a.totalRisk).slice(0, 10);
    }

    findShortestPath(graph, startId, endId) {
        // Simple BFS for shortest path
        const queue = [[startId]];
        const visited = new Set([startId]);

        while (queue.length > 0) {
            const path = queue.shift();
            const node = path[path.length - 1];

            if (node === endId) {
                return path;
            }

            // Find outgoing edges
            const outgoing = graph.edges.filter(e => e.source === node);

            for (const edge of outgoing) {
                if (!visited.has(edge.target)) {
                    visited.add(edge.target);
                    queue.push([...path, edge.target]);
                }
            }
        }

        return null;
    }

    // ========================================================================
    // Remediation Prioritization
    // ========================================================================

    prioritizeRemediation(findings) {
        // Create remediation plan based on multiple factors
        const prioritized = findings.map(f => {
            const remediationEffort = this.estimateRemediationEffort(f);
            const riskReduction = this.estimateRiskReduction(f);
            const roi = riskReduction / Math.max(remediationEffort, 1);

            return {
                ...f,
                remediationEffort,
                riskReduction,
                roi,
                priority: this.calculateRemediationPriority(f, roi)
            };
        });

        return prioritized.sort((a, b) => b.priority - a.priority);
    }

    estimateRemediationEffort(finding) {
        // Estimate person-hours needed
        let effort = 0;

        // Base effort by severity
        const baseEffort = {
            critical: 24,
            high: 16,
            medium: 8,
            low: 4,
            info: 2
        };
        effort = baseEffort[finding.severity] || 8;

        // Adjust based on domain
        if (finding.domain === 'Supply Chain Security') effort *= 1.5;
        if (finding.domain === 'Authentication') effort *= 1.3;

        // Adjust based on age (older = potentially more embedded)
        if (finding.ageInDays > 180) effort *= 1.4;
        else if (finding.ageInDays > 90) effort *= 1.2;

        return Math.round(effort);
    }

    estimateRiskReduction(finding) {
        // Estimate risk reduction from fixing this vulnerability
        const baseReduction = this.riskWeights.severity[finding.severity] || 30;

        let reduction = baseReduction;

        // Higher reduction if it blocks attack paths
        if (finding.networkReachable && !finding.authRequired) {
            reduction *= 1.8;
        }

        // Higher reduction if in KEV
        if (finding.inKEV) {
            reduction *= 2.0;
        }

        // Higher reduction if it's an entry point
        const type = this.classifyVulnerabilityType(finding);
        if (type === 'initial-access') {
            reduction *= 1.5;
        }

        return Math.round(reduction);
    }

    calculateRemediationPriority(finding, roi) {
        // Combine multiple factors for final priority
        let priority = roi * 100;

        // Boost critical findings
        if (finding.severity === 'critical') priority *= 1.5;

        // Boost KEV items
        if (finding.inKEV) priority *= 1.8;

        // Boost high EPSS
        if (finding.epssScore && parseFloat(finding.epssScore) > 0.1) {
            priority *= 1.4;
        }

        // Consider age (older = more urgent)
        if (finding.ageInDays > 90) priority *= 1.2;

        return Math.round(priority);
    }

    // ========================================================================
    // AI-Powered Remediation Suggestions
    // ========================================================================

    generateRemediationSuggestions(finding) {
        const suggestions = [];

        // Pattern-based remediation suggestions
        const text = (finding.title + ' ' + finding.description).toLowerCase();

        if (text.match(/sql injection/i)) {
            suggestions.push({
                type: 'code-fix',
                title: 'Implement Parameterized Queries',
                description: 'Replace string concatenation with prepared statements or ORM query builders.',
                effort: 'Medium',
                references: ['OWASP SQL Injection Prevention Cheat Sheet']
            });
        }

        if (text.match(/xss|cross-site scripting/i)) {
            suggestions.push({
                type: 'code-fix',
                title: 'Output Encoding',
                description: 'Implement context-aware output encoding for all user-supplied data.',
                effort: 'Medium',
                references: ['OWASP XSS Prevention Cheat Sheet']
            });
        }

        if (text.match(/authentication|auth/i)) {
            suggestions.push({
                type: 'architecture',
                title: 'Implement MFA',
                description: 'Add multi-factor authentication to protect against credential compromise.',
                effort: 'High',
                references: ['NIST 800-63B Digital Identity Guidelines']
            });
        }

        if (text.match(/encryption|crypto/i)) {
            suggestions.push({
                type: 'configuration',
                title: 'Enable TLS 1.3',
                description: 'Upgrade to TLS 1.3 and disable older protocols (TLS 1.0, 1.1).',
                effort: 'Low',
                references: ['NIST SP 800-52 Rev. 2']
            });
        }

        if (text.match(/secret|key|token|password/i)) {
            suggestions.push({
                type: 'tool',
                title: 'Use Secrets Manager',
                description: 'Migrate hardcoded secrets to a dedicated secrets management solution (AWS Secrets Manager, HashiCorp Vault, etc.).',
                effort: 'High',
                references: ['OWASP Secrets Management Cheat Sheet']
            });
        }

        // Generic suggestions based on severity
        if (finding.severity === 'critical' || finding.severity === 'high') {
            suggestions.push({
                type: 'process',
                title: 'Emergency Patch',
                description: 'Deploy fix within 48 hours. Consider emergency change process.',
                effort: 'High',
                priority: 'Immediate'
            });
        }

        // If no specific suggestions, add generic one
        if (suggestions.length === 0) {
            suggestions.push({
                type: 'general',
                title: 'Vendor Patch Available',
                description: 'Check with vendor for latest security patches and updates.',
                effort: 'Low',
                references: []
            });
        }

        return suggestions;
    }

    // ========================================================================
    // Trend Analysis & Prediction
    // ========================================================================

    analyzeTrends(historicalScans) {
        if (historicalScans.length < 2) {
            return null;
        }

        const trends = {
            securityDebtTrend: this.calculateTrend(historicalScans, 'securityDebtScore'),
            criticalTrend: this.calculateTrend(historicalScans, 'metrics.critical'),
            highTrend: this.calculateTrend(historicalScans, 'metrics.high'),
            mediumTrend: this.calculateTrend(historicalScans, 'metrics.medium'),
            prediction: this.predictFutureState(historicalScans)
        };

        return trends;
    }

    calculateTrend(scans, metric) {
        const values = scans.map(scan => this.getNestedValue(scan, metric));

        if (values.length < 2) return { direction: 'stable', change: 0 };

        const first = values[0];
        const last = values[values.length - 1];
        const change = last - first;
        const percentChange = (change / first) * 100;

        return {
            direction: change > 0 ? 'increasing' : change < 0 ? 'decreasing' : 'stable',
            change: Math.round(percentChange),
            values
        };
    }

    getNestedValue(obj, path) {
        return path.split('.').reduce((curr, key) => curr?.[key], obj) || 0;
    }

    predictFutureState(scans) {
        // Simple linear regression for prediction
        const recentScans = scans.slice(-10);
        const debtScores = recentScans.map(s => s.securityDebtScore || 0);

        if (debtScores.length < 3) return null;

        // Calculate slope
        const n = debtScores.length;
        const xMean = (n - 1) / 2;
        const yMean = debtScores.reduce((sum, val) => sum + val, 0) / n;

        let numerator = 0;
        let denominator = 0;

        for (let i = 0; i < n; i++) {
            const xDiff = i - xMean;
            const yDiff = debtScores[i] - yMean;
            numerator += xDiff * yDiff;
            denominator += xDiff * xDiff;
        }

        const slope = numerator / denominator;
        const intercept = yMean - slope * xMean;

        // Predict next 3 scans
        const predictions = [];
        for (let i = 1; i <= 3; i++) {
            predictions.push(Math.round(intercept + slope * (n + i - 1)));
        }

        return {
            trend: slope > 5 ? 'worsening' : slope < -5 ? 'improving' : 'stable',
            predictions
        };
    }
}

// Export for use in main application
if (typeof window !== 'undefined') {
    window.MLEngine = MLEngine;
}
