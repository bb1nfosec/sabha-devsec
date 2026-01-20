// ============================================================================
// SABHA Threat Intelligence Module
// Real-time CVE/NVD/EPSS/CISA KEV Integration
// ============================================================================

class ThreatIntelligenceEngine {
    constructor() {
        this.cveCache = new Map();
        this.epssCache = new Map();
        this.kevCache = new Set();
        this.mitreAttackMap = this.initMitreMap();
        this.lastUpdate = null;
    }

    // ========================================================================
    // CVE Enrichment via NVD API
    // ========================================================================

    async enrichWithCVEData(findings) {
        const enrichedFindings = [];

        for (const finding of findings) {
            let enriched = { ...finding };

            if (finding.cveId) {
                const cveData = await this.getCVEData(finding.cveId);
                if (cveData) {
                    enriched = {
                        ...enriched,
                        cvssV3Score: cveData.cvssV3?.baseScore || enriched.cvssScore,
                        cvssV3Vector: cveData.cvssV3?.vectorString,
                        cveDescription: cveData.description,
                        cvePublished: cveData.publishedDate,
                        cveModified: cveData.lastModifiedDate,
                        cweId: cveData.cwe,
                        references: cveData.references
                    };

                    // Get EPSS score
                    const epssData = await this.getEPSSScore(finding.cveId);
                    if (epssData) {
                        enriched.epssScore = epssData.probability;
                        enriched.epssPercentile = epssData.percentile;
                    }

                    // Check CISA KEV
                    enriched.inKEV = this.isInCISAKEV(finding.cveId);
                }
            }

            // Add MITRE ATT&CK mapping
            enriched.mitreAttack = this.mapToMitreAttack(finding);

            enrichedFindings.push(enriched);
        }

        return enrichedFindings;
    }

    async getCVEData(cveId) {
        // Check cache first
        if (this.cveCache.has(cveId)) {
            return this.cveCache.get(cveId);
        }

        try {
            // NOTE: Due to CORS, this won't work directly from browser
            // In production, you'd need a proxy server or use the optional API server
            // For now, we'll use mock data for demonstration

            const mockData = this.getMockCVEData(cveId);
            this.cveCache.set(cveId, mockData);
            return mockData;

            /* Actual API call (requires proxy):
            const response = await fetch(
                `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
                {
                    headers: {
                        'Accept': 'application/json'
                    }
                }
            );
            
            if (response.ok) {
                const data = await response.json();
                const vuln = data.vulnerabilities?.[0]?.cve;
                
                if (vuln) {
                    const cveData = {
                        cveId: vuln.id,
                        description: vuln.descriptions?.find(d => d.lang === 'en')?.value,
                        publishedDate: vuln.published,
                        lastModifiedDate: vuln.lastModified,
                        cvssV3: vuln.metrics?.cvssMetricV31?.[0]?.cvssData,
                        cvssV2: vuln.metrics?.cvssMetricV2?.[0]?.cvssData,
                        cwe: vuln.weaknesses?.[0]?.description?.[0]?.value,
                        references: vuln.references?.map(r => r.url) || []
                    };
                    
                    this.cveCache.set(cveId, cveData);
                    return cveData;
                }
            }
            */
        } catch (error) {
            console.error(`Error fetching CVE data for ${cveId}:`, error);
        }

        return null;
    }

    getMockCVEData(cveId) {
        // Mock CVE data for demonstration
        const baseCVSS = 7.0 + Math.random() * 3;

        return {
            cveId,
            description: `Mock description for ${cveId}. This vulnerability represents a security flaw that could allow attackers to compromise system integrity.`,
            publishedDate: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString(),
            lastModifiedDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
            cvssV3: {
                baseScore: baseCVSS,
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                baseSeverity: baseCVSS >= 9 ? 'CRITICAL' : baseCVSS >= 7 ? 'HIGH' : baseCVSS >= 4 ? 'MEDIUM' : 'LOW'
            },
            cwe: `CWE-${Math.floor(100 + Math.random() * 900)}`,
            references: [
                'https://nvd.nist.gov/vuln/detail/' + cveId,
                'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cveId
            ]
        };
    }

    async getEPSSScore(cveId) {
        // Check cache
        if (this.epssCache.has(cveId)) {
            return this.epssCache.get(cveId);
        }

        try {
            // Mock EPSS data for demonstration
            const mockEPSS = {
                cveId,
                probability: (Math.random() * 0.3).toFixed(6), // 0-30% exploitation probability
                percentile: (Math.random() * 100).toFixed(2)   // 0-100 percentile
            };

            this.epssCache.set(cveId, mockEPSS);
            return mockEPSS;

            /* Actual API call:
            const response = await fetch(
                `https://api.first.org/data/v1/epss?cve=${cveId}`,
                {
                    headers: {
                        'Accept': 'application/json'
                    }
                }
            );
            
            if (response.ok) {
                const data = await response.json();
                const epssData = data.data?.[0];
                
                if (epssData) {
                    const result = {
                        cveId: epssData.cve,
                        probability: epssData.epss,
                        percentile: epssData.percentile
                    };
                    
                    this.epssCache.set(cveId, result);
                    return result;
                }
            }
            */
        } catch (error) {
            console.error(`Error fetching EPSS data for ${cveId}:`, error);
        }

        return null;
    }

    // ========================================================================
    // CISA KEV (Known Exploited Vulnerabilities) Catalog
    // ========================================================================

    async loadCISAKEV() {
        try {
            // Mock KEV data - in production, fetch from CISA
            const mockKEVs = [
                'CVE-2023-23397',
                'CVE-2023-21608',
                'CVE-2023-21715',
                'CVE-2022-41040',
                'CVE-2022-41082',
                'CVE-2021-44228', // Log4Shell
                'CVE-2021-26855', // ProxyLogon
                'CVE-2020-1472',  // ZeroLogon
            ];

            mockKEVs.forEach(cve => this.kevCache.add(cve));
            this.lastUpdate = new Date();

            /* Actual API call:
            const response = await fetch(
                'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
            );
            
            if (response.ok) {
                const data = await response.json();
                data.vulnerabilities?.forEach(vuln => {
                    this.kevCache.add(vuln.cveID);
                });
                this.lastUpdate = new Date();
            }
            */
        } catch (error) {
            console.error('Error loading CISA KEV catalog:', error);
        }
    }

    isInCISAKEV(cveId) {
        return this.kevCache.has(cveId);
    }

    // ========================================================================
    // MITRE ATT&CK Mapping
    // ========================================================================

    initMitreMap() {
        // Simplified MITRE ATT&CK mapping based on vulnerability characteristics
        return {
            'authentication': {
                techniques: ['T1078', 'T1110', 'T1556'],
                tactics: ['Credential Access', 'Persistence'],
                names: ['Valid Accounts', 'Brute Force', 'Modify Authentication Process']
            },
            'api': {
                techniques: ['T1190', 'T1212'],
                tactics: ['Initial Access', 'Lateral Movement'],
                names: ['Exploit Public-Facing Application', 'Exploitation for Credential Access']
            },
            'sql injection': {
                techniques: ['T1190', 'T1213'],
                tactics: ['Initial Access', 'Collection'],
                names: ['Exploit Public-Facing Application', 'Data from Information Repositories']
            },
            'xss': {
                techniques: ['T1189', 'T1059'],
                tactics: ['Initial Access', 'Execution'],
                names: ['Drive-by Compromise', 'Command and Scripting Interpreter']
            },
            'rce': {
                techniques: ['T1190', 'T1203', 'T1059'],
                tactics: ['Initial Access', 'Execution'],
                names: ['Exploit Public-Facing Application', 'Exploitation for Client Execution', 'Command and Scripting Interpreter']
            },
            'deserialization': {
                techniques: ['T1190', 'T1059'],
                tactics: ['Initial Access', 'Execution'],
                names: ['Exploit Public-Facing Application', 'Command and Scripting Interpreter']
            },
            'ssrf': {
                techniques: ['T1190', 'T1599'],
                tactics: ['Initial Access', 'Defense Evasion'],
                names: ['Exploit Public-Facing Application', 'Network Boundary Bridging']
            },
            'csrf': {
                techniques: ['T1189', 'T1552'],
                tactics: ['Initial Access', 'Credential Access'],
                names: ['Drive-by Compromise', 'Unsecured Credentials']
            },
            'encryption': {
                techniques: ['T1213', 'T1005'],
                tactics: ['Collection', 'Collection'],
                names: ['Data from Information Repositories', 'Data from Local System']
            },
            'secret': {
                techniques: ['T1552', 'T1078'],
                tactics: ['Credential Access', 'Persistence'],
                names: ['Unsecured Credentials', 'Valid Accounts']
            },
            'privilege': {
                techniques: ['T1068', 'T1548'],
                tactics: ['Privilege Escalation', 'Defense Evasion'],
                names: ['Exploitation for Privilege Escalation', 'Abuse Elevation Control Mechanism']
            },
            'path traversal': {
                techniques: ['T1083', 'T1005'],
                tactics: ['Discovery', 'Collection'],
                names: ['File and Directory Discovery', 'Data from Local System']
            }
        };
    }

    mapToMitreAttack(finding) {
        const text = (finding.title + ' ' + finding.description).toLowerCase();
        const matches = [];

        for (const [keyword, mapping] of Object.entries(this.mitreAttackMap)) {
            if (text.includes(keyword)) {
                matches.push({
                    keyword,
                    techniques: mapping.techniques,
                    tactics: mapping.tactics,
                    names: mapping.names
                });
            }
        }

        if (matches.length === 0) {
            // Default mapping
            return [{
                keyword: 'general',
                techniques: ['T1190'],
                tactics: ['Initial Access'],
                names: ['Exploit Public-Facing Application']
            }];
        }

        // Deduplicate and return
        const uniqueTechniques = [...new Set(matches.flatMap(m => m.techniques))];
        const uniqueTactics = [...new Set(matches.flatMap(m => m.tactics))];
        const uniqueNames = [...new Set(matches.flatMap(m => m.names))];

        return [{
            techniques: uniqueTechniques,
            tactics: uniqueTactics,
            names: uniqueNames
        }];
    }

    // ========================================================================
    // Priority Scoring with Threat Intelligence
    // ========================================================================

    calculateThreatScore(finding) {
        let score = 0;

        // Base severity weight
        const severityWeights = {
            'critical': 50,
            'high': 30,
            'medium': 15,
            'low': 5
        };
        score += severityWeights[finding.severity] || 10;

        // CVSS score (0-10)
        if (finding.cvssV3Score) {
            score += finding.cvssV3Score * 3;
        } else if (finding.cvssScore) {
            score += finding.cvssScore * 3;
        }

        // EPSS score (probability of exploitation in 30 days)
        if (finding.epssScore) {
            const epssProbability = parseFloat(finding.epssScore);
            score += epssProbability * 100; // 0-30 points
        }

        // CISA KEV - significantly increases priority
        if (finding.inKEV) {
            score += 40;
        }

        // Public exploit availability
        if (finding.publicExploit) {
            score += 20;
        }

        // Age factor (older vulnerabilities get higher priority)
        if (finding.ageInDays) {
            score += Math.min(finding.ageInDays / 3, 20); // Max 20 points for age
        }

        // Network reachability
        if (finding.networkReachable) {
            score += 15;
        }

        // Authentication not required
        if (!finding.authRequired) {
            score += 10;
        }

        return Math.round(score);
    }

    prioritizeFindings(findings) {
        return findings.map(f => ({
            ...f,
            threatScore: this.calculateThreatScore(f)
        })).sort((a, b) => b.threatScore - a.threatScore);
    }

    // ========================================================================
    // Threat Actor Profiling (Mock)
    // ========================================================================

    getThreatActorProfile(finding) {
        // Mock threat actor correlation based on techniques
        const profiles = [
            {
                name: 'APT28',
                aka: 'Fancy Bear',
                motivation: 'State-sponsored espionage',
                targetedSectors: ['Government', 'Defense', 'Energy'],
                commonTechniques: ['T1078', 'T1110', 'T1190']
            },
            {
                name: 'Lazarus Group',
                aka: 'Hidden Cobra',
                motivation: 'Financial gain, espionage',
                targetedSectors: ['Financial', 'Cryptocurrency', 'Defense'],
                commonTechniques: ['T1190', 'T1059', 'T1552']
            },
            {
                name: 'FIN7',
                aka: 'Carbanak',
                motivation: 'Financial gain',
                targetedSectors: ['Retail', 'Hospitality', 'Financial'],
                commonTechniques: ['T1078', 'T1552', 'T1213']
            }
        ];

        // Match based on MITRE techniques
        if (finding.mitreAttack && finding.mitreAttack[0]) {
            const findingTechniques = finding.mitreAttack[0].techniques;

            for (const profile of profiles) {
                const matchCount = findingTechniques.filter(t =>
                    profile.commonTechniques.includes(t)
                ).length;

                if (matchCount >= 2) {
                    return profile;
                }
            }
        }

        return null;
    }

    // ========================================================================
    // Statistics & Reporting
    // ========================================================================

    generateThreatIntelReport(findings) {
        const enrichedFindings = findings.filter(f => f.cveId || f.epssScore || f.inKEV);

        return {
            totalFindings: findings.length,
            enrichedCount: enrichedFindings.length,
            kevCount: findings.filter(f => f.inKEV).length,
            highEPSS: findings.filter(f => f.epssScore && parseFloat(f.epssScore) > 0.1).length,
            criticalCVSS: findings.filter(f => (f.cvssV3Score || f.cvssScore) >= 9.0).length,
            topMitreTactics: this.getTopMitreTactics(findings),
            topMitreTechniques: this.getTopMitreTechniques(findings),
            threatActors: this.identifyThreatActors(findings)
        };
    }

    getTopMitreTactics(findings) {
        const tacticCounts = {};

        findings.forEach(f => {
            if (f.mitreAttack) {
                f.mitreAttack.forEach(m => {
                    m.tactics?.forEach(tactic => {
                        tacticCounts[tactic] = (tacticCounts[tactic] || 0) + 1;
                    });
                });
            }
        });

        return Object.entries(tacticCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([tactic, count]) => ({ tactic, count }));
    }

    getTopMitreTechniques(findings) {
        const techniqueCounts = {};

        findings.forEach(f => {
            if (f.mitreAttack) {
                f.mitreAttack.forEach(m => {
                    m.techniques?.forEach((technique, idx) => {
                        const name = m.names?.[idx] || technique;
                        const key = `${technique}: ${name}`;
                        techniqueCounts[key] = (techniqueCounts[key] || 0) + 1;
                    });
                });
            }
        });

        return Object.entries(techniqueCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([technique, count]) => ({ technique, count }));
    }

    identifyThreatActors(findings) {
        const actors = new Map();

        findings.forEach(f => {
            const profile = this.getThreatActorProfile(f);
            if (profile) {
                if (actors.has(profile.name)) {
                    actors.get(profile.name).count++;
                } else {
                    actors.set(profile.name, { ...profile, count: 1 });
                }
            }
        });

        return Array.from(actors.values()).sort((a, b) => b.count - a.count);
    }
}

// Export for use in main application
if (typeof window !== 'undefined') {
    window.ThreatIntelligenceEngine = ThreatIntelligenceEngine;
}
