# CI/CD Integration Guide

Complete guide for integrating Valeris into your CI/CD pipelines.

## Table of Contents

- [Quick Start](#quick-start)
- [Exit Codes](#exit-codes)
- [Severity Filtering](#severity-filtering)
- [Pipeline Examples](#pipeline-examples)
- [Best Practices](#best-practices)

---

## Quick Start

### Runtime Container Scanning

```bash
# Fail pipeline if high severity findings exist
valeris scan --fail-on high

# Quiet mode - no output, only exit code
valeris scan --quiet --fail-on high

# With container filtering
valeris scan --state running --fail-on medium
valeris scan --container production-* --fail-on high
```

### Dockerfile Scanning

```bash
# Fail pipeline if critical Dockerfile issues exist
valeris docker-file -p Dockerfile -r ./rules/dockerfile --fail-on high

# Quiet mode for build scripts
valeris df -p Dockerfile -r ./rules/dockerfile --quiet --fail-on medium

# Only check specific rules
valeris df -p Dockerfile -r ./rules/dockerfile --only DF001,DF002,DF006 --fail-on high
```

### Combined Pipeline

```bash
# Scan both Dockerfile AND running containers
valeris df -p Dockerfile -r ./rules/dockerfile --fail-on high && \
valeris scan --fail-on high
```

---

## Exit Codes

Valeris uses standard exit codes for CI/CD integration:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Success - no findings above threshold |
| `1` | Failure - findings found above threshold (when using `--fail-on`) |
| `2` | Invalid CLI usage |

### Example

```bash
#!/bin/bash
valeris scan --fail-on high

if [ $? -eq 0 ]; then
  echo "✅ No critical security issues found"
else
  echo "❌ Critical security issues detected!"
  exit 1
fi
```

---

## Severity Filtering

### Available Severity Levels

From lowest to highest:
1. `informative` - Informational findings
2. `low` - Low severity issues
3. `medium` - Medium severity issues
4. `high` - High severity issues

### Filter by Exact Severities

```bash
# Show only high severity findings
valeris scan --severity high

# Show multiple specific levels
valeris scan --severity medium,high
```

### Filter by Minimum Severity

```bash
# Show medium and above (medium + high)
valeris scan --min-severity medium

# Show only high severity
valeris scan --min-severity high
```

### fail-on Behavior

The `--fail-on` flag checks if **any** findings exist at or above the specified level:

```bash
# Exit 1 if any high severity findings exist
valeris scan --fail-on high

# Exit 1 if any medium or high severity findings exist
valeris scan --fail-on medium

# Exit 1 if any findings exist (except informative)
valeris scan --fail-on low
```

---

## Pipeline Examples

### GitHub Actions

```yaml
name: Container Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Start test containers
        run: docker-compose up -d

      - name: Install Valeris
        run: |
          cargo install --git https://github.com/rsgbengi/valeris.git --locked

      - name: Scan Dockerfile
        run: |
          valeris docker-file -p Dockerfile -r ./rules/dockerfile --fail-on high

      - name: Scan containers
        run: |
          valeris scan --state running --fail-on high

      - name: Export findings on failure
        if: failure()
        run: |
          valeris scan --format json --output container-findings.json
          valeris df -p Dockerfile -r ./rules/dockerfile -f json -o dockerfile-findings.json

      - name: Upload findings
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: security-findings
          path: |
            container-findings.json
            dockerfile-findings.json
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: rust:latest

  before_script:
    - cargo install --git https://github.com/rsgbengi/valeris.git --locked
    - docker-compose up -d

  script:
    - valeris scan --state running --fail-on high --format json --output findings.json

  artifacts:
    when: on_failure
    paths:
      - findings.json
    expire_in: 30 days

  allow_failure: false
```

### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Start Containers') {
            steps {
                sh 'docker-compose up -d'
            }
        }

        stage('Security Scan') {
            steps {
                script {
                    def scanResult = sh(
                        script: 'valeris scan --fail-on high',
                        returnStatus: true
                    )

                    if (scanResult != 0) {
                        // Export findings for analysis
                        sh 'valeris scan --format json --output findings.json'
                        archiveArtifacts artifacts: 'findings.json'
                        error('Critical security issues found!')
                    }
                }
            }
        }
    }

    post {
        always {
            sh 'docker-compose down'
        }
    }
}
```

### CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/rust:1.71

    steps:
      - checkout

      - setup_remote_docker:
          version: 20.10.14

      - run:
          name: Install Valeris
          command: |
            cargo install --git https://github.com/rsgbengi/valeris.git --locked

      - run:
          name: Start containers
          command: docker-compose up -d

      - run:
          name: Security scan
          command: |
            valeris scan --state running --fail-on high

      - run:
          name: Export findings on failure
          when: on_fail
          command: |
            valeris scan --format json --output findings.json

      - store_artifacts:
          path: findings.json
          when: on_fail

workflows:
  version: 2
  build-and-scan:
    jobs:
      - security-scan
```

---

## Best Practices

### 1. Use Quiet Mode in Scripts

```bash
# Bad - clutters CI logs
valeris scan --fail-on high

# Good - clean exit code only
valeris scan --quiet --fail-on high
```

### 2. Export Findings on Failure

```bash
#!/bin/bash

# Run scan
valeris scan --quiet --fail-on high
SCAN_RESULT=$?

# If failed, export detailed findings
if [ $SCAN_RESULT -ne 0 ]; then
  echo "Security issues detected. Exporting findings..."
  valeris scan --format json --output findings.json
  exit 1
fi
```

### 3. Progressive Severity Thresholds

Different thresholds for different branches:

```yaml
# .github/workflows/security.yml
- name: Scan (main branch)
  if: github.ref == 'refs/heads/main'
  run: valeris scan --fail-on high

- name: Scan (develop branch)
  if: github.ref == 'refs/heads/develop'
  run: valeris scan --fail-on medium

- name: Scan (feature branches)
  if: startsWith(github.ref, 'refs/heads/feature/')
  run: valeris scan --fail-on low
```

### 4. Filter by Container Patterns

Only scan production containers:

```bash
valeris scan --container "*-prod" --fail-on medium
```

### 5. Combine with Other Filters

```bash
# Only scan specific detectors on running containers
valeris scan \
  --state running \
  --only privileged_mode,capabilities,secrets_in_env \
  --fail-on high
```

---

## Advanced Examples

### Baseline Comparison

Save baseline and compare:

```bash
# Save baseline on first run
valeris scan --format json --output baseline.json

# Later, compare (manual for now)
valeris scan --format json --output current.json
diff baseline.json current.json
```

### Multi-Stage Pipeline

```bash
#!/bin/bash
set -e

echo "Stage 1: Quick scan for critical issues"
valeris scan --quiet --only privileged_mode,secrets_in_env --fail-on high

echo "Stage 2: Full scan for all high severity"
valeris scan --quiet --fail-on high

echo "Stage 3: Export detailed report"
valeris scan --min-severity medium --format json --output full-report.json

echo "✅ All security checks passed"
```

### Slack Notification on Failure

```bash
#!/bin/bash

valeris scan --quiet --fail-on high
RESULT=$?

if [ $RESULT -ne 0 ]; then
  # Export findings
  valeris scan --format json --output findings.json

  # Count findings
  HIGH_COUNT=$(jq '[.[] | .findings[] | select(.risk == "High")] | length' findings.json)

  # Send to Slack
  curl -X POST $SLACK_WEBHOOK_URL \
    -H 'Content-Type: application/json' \
    -d "{
      \"text\": \"🚨 Security Scan Failed\",
      \"attachments\": [{
        \"color\": \"danger\",
        \"text\": \"Found $HIGH_COUNT high severity issues\"
      }]
    }"

  exit 1
fi
```

---

## Troubleshooting

### Issue: Scan passes in CI but fails locally

**Cause:** Different containers running

**Solution:**
```bash
# List what's being scanned
valeris scan --state running --container "*"

# Be explicit about state
valeris scan --state running,paused
```

### Issue: Too many false positives

**Solution:** Use allowlist (manual for now)
```bash
# Exclude specific detectors
valeris scan --exclude readonly_rootfs,no_healthcheck --fail-on high
```

### Issue: Exit code always 0

**Cause:** Forgot `--fail-on`

**Solution:**
```bash
# Bad
valeris scan --quiet

# Good
valeris scan --quiet --fail-on high
```

---

## See Also

- [CLI Reference](CLI.md) - Complete CLI documentation
- [Quick Start Guide](guides/quick-start.md) - Getting started
- [Examples](../examples/) - More pipeline examples
