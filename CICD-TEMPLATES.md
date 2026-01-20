# Sabha-DevSec CI/CD Integration Templates

## GitHub Actions Workflow

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan with Sabha

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # Run daily at 2 AM UTC
    - cron: '0 2 * * *'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Run security scanners
        run: |
          # Example: Run multiple scanners
          # npm audit --json > npm-audit.json
          # semgrep --config auto --json > semgrep.json
          # snyk test --json > snyk.json
          echo "Run your security scanners here"
      
      - name: Setup Node.js for Sabha
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install Sabha CLI
        run: |
          npm install -g sabha-devsec-cli
          # Or use npx: npx sabha-devsec-cli
      
      - name: Analyze with Sabha
        env:
          SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK_URL }}
        run: |
          sabha analyze \
            --file security-results.json \
            --output sabha-report.json \
            --format json \
            --fail-on critical \
            --slack "$SLACK_WEBHOOK"
      
      - name: Upload Sabha Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: sabha-security-report
          path: sabha-report.json
      
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('sabha-report.json', 'utf8'));
            
            const comment = `## 🔒 Sabha Security Scan Results
            
            **Critical:** ${report.metrics.critical}
            **High:** ${report.metrics.high}
            **Medium:** ${report.metrics.medium}
            **Low:** ${report.metrics.low}
            
            **Security Debt Score:** ${report.securityDebtScore}
            **Compliance Status:** ${report.complianceReport.overallStatus}
            
            [View Full Report](https://github.com/${{github.repository}}/actions/runs/${{github.run_id}})
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

---

## GitLab CI/CD Pipeline

Create `.gitlab-ci.yml`:

```yaml
stages:
  - security
  - report

variables:
  SABHA_OUTPUT: "sabha-report.json"

security_scan:
  stage: security
  image: node:18-alpine
  before_script:
    - npm install -g sabha-devsec-cli
  script:
    - |
      # Run security scanners
      # npm audit --json > npm-audit.json
      
      # Analyze with Sabha
      sabha analyze \
        --file security-results.json \
        --output $SABHA_OUTPUT \
        --fail-on critical \
        --webhook $WEBHOOK_URL \
        --slack $SLACK_WEBHOOK
  artifacts:
    reports:
      junit: sabha-report.json
    paths:
      - sabha-report.json
    expire_in: 30 days
  allow_failure: false
  only:
    - main
    - merge_requests

generate_report:
  stage: report
  image: node:18-alpine
  dependencies:
    - security_scan
  script:
    - echo "Security scan complete"
    - cat sabha-report.json | jq  '.metrics'
  only:
    - main
```

---

## Jenkins Pipeline

Create `Jenkinsfile`:

```groovy
pipeline {
    agent any
    
    environment {
        SLACK_WEBHOOK = credentials('slack-webhook-url')
        SABHA_OUTPUT = 'sabha-report.json'
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Run security scanners
                    sh '''
                        # npm audit --json > npm-audit.json
                        # semgrep --config auto --json > semgrep.json
                        echo "Run security scanners"
                    '''
                }
            }
        }
        
        stage('Sabha Analysis') {
            steps {
                nodejs(nodeJSInstallationName: 'Node 18') {
                    sh '''
                        npm install -g sabha-devsec-cli
                        
                        sabha analyze \
                            --file security-results.json \
                            --output ${SABHA_OUTPUT} \
                            --fail-on critical \
                            --slack ${SLACK_WEBHOOK}
                    '''
                }
            }
        }
        
        stage('Publish Report') {
            steps {
                publishHTML([
                    reportDir: '.',
                    reportFiles: 'sabha-report.json',
                    reportName: 'Sabha Security Report'
                ])
                
                archiveArtifacts artifacts: 'sabha-report.json', fingerprint: true
            }
        }
    }
    
    post {
        always {
            script {
                def report = readJSON file: 'sabha-report.json'
                
                if (report.metrics.critical > 0) {
                    currentBuild.result = 'FAILURE'
                    error("Critical security findings detected!")
                }
            }
        }
    }
}
```

---

## CircleCI Configuration

Create `.circleci/config.yml`:

```yaml
version: 2.1

executors:
  node-executor:
    docker:
      - image: cimg/node:18.0
    working_directory: ~/project

jobs:
  security-scan:
    executor: node-executor
    steps:
      - checkout
      
      - run:
          name: Install Sabha CLI
          command: npm install -g sabha-devsec-cli
      
      - run:
          name: Run Security Scanners
          command: |
            # Add your scanner commands here
            echo "Running security scanners..."
      
      - run:
          name: Analyze with Sabha
          command: |
            sabha analyze \
              --file security-results.json \
              --output sabha-report.json \
              --fail-on critical \
              --webhook $WEBHOOK_URL
      
      - store_artifacts:
          path: sabha-report.json
          destination: security-reports
      
      - store_test_results:
          path: sabha-report.json

workflows:
  version: 2
  security-workflow:
    jobs:
      - security-scan:
          context: security-scanning
          filters:
            branches:
              only:
                - main
                - develop
```

---

## Docker Integration

Create `Dockerfile`:

```dockerfile
FROM node:18-alpine

# Install Sabha CLI
RUN npm install -g sabha-devsec-cli

# Set working directory
WORKDIR /app

# Copy scan results
COPY security-results.json .

# Run analysis
ENTRYPOINT ["sabha", "analyze", "--file", "security-results.json"]
```

Usage:
```bash
docker build -t sabha-scanner .
docker run -v $(pwd)/results:/app sabha-scanner --output /app/report.json
```

---

## Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

echo "🔍 Running Sabha security check..."

# Run quick security scan
npm audit --json > /tmp/audit.json 2>/dev/null || true

# Analyze with Sabha
sabha analyze \
    --file /tmp/audit.json \
    --output /tmp/sabha.json \
    --fail-on critical \
    --quiet

RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo "❌ Security check failed! Critical findings detected."
    echo "   Run: sabha analyze --file /tmp/audit.json"
    exit 1
fi

echo "✅ Security check passed"
exit 0
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

---

## Kubernetes CronJob

Create `k8s/security-scan-cronjob.yaml`:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: sabha-security-scan
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: sabha-scanner
            image: node:18-alpine
            command:
            - /bin/sh
            - -c
            - |
              npm install -g sabha-devsec-cli
              
              sabha analyze \
                --file /data/security-results.json \
                --output /data/sabha-report.json \
                --webhook $WEBHOOK_URL \
                --slack $SLACK_WEBHOOK
            env:
            - name: WEBHOOK_URL
              valueFrom:
                secretKeyRef:
                  name: sabha-secrets
                  key: webhook-url
            - name: SLACK_WEBHOOK
              valueFrom:
                secretKeyRef:
                  name: sabha-secrets
                  key: slack-webhook
            volumeMounts:
            - name: scan-data
              mountPath: /data
          volumes:
          - name: scan-data
            persistentVolumeClaim:
              claimName: security-scan-pvc
          restartPolicy: OnFailure
```

---

## Integration with Jira (via REST API)

```javascript
// jira-integration.js
const fetch = require('node-fetch');

async function createJiraTicket(finding) {
    const jiraUrl = process.env.JIRA_URL;
    const jiraToken = process.env.JIRA_TOKEN;
    
    const ticket = {
        fields: {
            project: { key: 'SEC' },
            summary: `[${finding.severity.toUpperCase()}] ${finding.title}`,
            description: `
Security Finding from Sabha-DevSec

*Severity:* ${finding.severity}
*Domain:* ${finding.domain}
*CVE:* ${finding.cveId || 'N/A'}
*EPSS Score:* ${finding.epssScore || 'N/A'}
*In CISA KEV:* ${finding.inKEV ? 'YES' : 'No'}

*Description:*
${finding.description}

*Remediation Suggestions:*
${finding.aiSuggestions?.map(s => `- ${s.title}`).join('\n')}

*ML Risk Score:* ${finding.mlRiskScore}
*Threat Score:* ${finding.threatScore}
            `,
            issuetype: { name: 'Bug' },
            priority: { name: finding.severity === 'critical' ? 'Highest' : 'High' },
            labels: ['security', 'sabha', finding.severity]
        }
    };
    
    const response = await fetch(`${jiraUrl}/rest/api/2/issue`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${jiraToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(ticket)
    });
    
    return await response.json();
}
```

---

## Usage Examples

### Basic CI/CD Integration
```bash
# In your CI pipeline
sabha analyze --file results.json --fail-on high
```

### With Notifications
```bash
sabha analyze \
  --file scan.json \
  --slack https://hooks.slack.com/services/YOUR/WEBHOOK \
  --teams https://outlook.office.com/webhook/YOUR/WEBHOOK \
  --fail-on critical
```

### Generate HTML Report
```bash
sabha analyze --file scan.json --format html --output report.html
```

### Quiet Mode for Scripting
```bash
sabha analyze --file scan.json --quiet && echo "Scan passed"
```
