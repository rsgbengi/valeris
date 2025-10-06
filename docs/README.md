# Valeris Documentation

Welcome to the Valeris documentation! This guide will help you understand, use, and contribute to Valeris.

## 📚 Table of Contents

### Getting Started
- [Quick Start Guide](guides/quick-start.md) - Get up and running in 5 minutes
- [Installation](guides/installation.md) - Detailed installation instructions
- [Configuration](guides/configuration.md) - Configure Valeris for your environment

### Architecture
- [Architecture Overview](architecture/overview.md) - System design and components
- [Rule Engine](architecture/rule-engine.md) - How the YAML rule engine works
- [Custom Rules](architecture/custom-rules.md) - Creating your own detection rules

### Rules Reference
- [Dockerfile Rules](rules/dockerfile-rules.md) - All 37 Dockerfile security rules
- [Runtime Rules](rules/runtime-rules.md) - All 36 container runtime rules
- [Severity Levels](rules/severity-levels.md) - Understanding risk classification

### Usage Guides
- [Scanning Dockerfiles](guides/dockerfile-scanning.md) - Static analysis guide
- [Scanning Containers](guides/runtime-scanning.md) - Runtime analysis guide
- [Output Formats](guides/output-formats.md) - JSON, CSV, and table outputs
- [CI/CD Integration](guides/ci-cd-integration.md) - Automate security scanning
- [Advanced Filtering](guides/filtering.md) - Filter by rules, severity, state

### Contributing
- [Contributing Guide](contributing/CONTRIBUTING.md) - How to contribute
- [Development Setup](contributing/development.md) - Set up dev environment
- [Writing Tests](contributing/testing.md) - Testing guidelines
- [Code Style](contributing/code-style.md) - Coding standards

## 🚀 Quick Links

### For Users
- **New to Valeris?** → [Quick Start Guide](guides/quick-start.md)
- **Need help?** → [Troubleshooting](guides/troubleshooting.md)
- **Want examples?** → [Example Scans](guides/examples.md)

### For Developers
- **Architecture?** → [Overview](architecture/overview.md)
- **Add rules?** → [Custom Rules](architecture/custom-rules.md)
- **Contribute?** → [Contributing](contributing/CONTRIBUTING.md)

### Reference
- **Dockerfile rules?** → [Dockerfile Rules](rules/dockerfile-rules.md)
- **Runtime rules?** → [Runtime Rules](rules/runtime-rules.md)
- **CI/CD setup?** → [CI/CD Guide](guides/ci-cd-integration.md)

## 📖 Documentation Structure

```
docs/
├── README.md                          # This file
│
├── guides/                            # User guides
│   ├── quick-start.md                 # 5-minute getting started
│   ├── installation.md                # Detailed installation
│   ├── configuration.md               # Configuration options
│   ├── dockerfile-scanning.md         # Dockerfile analysis guide
│   ├── runtime-scanning.md            # Container scanning guide
│   ├── output-formats.md              # Export formats
│   ├── ci-cd-integration.md           # CI/CD setup
│   ├── filtering.md                   # Advanced filtering
│   ├── troubleshooting.md             # Common issues
│   └── examples.md                    # Usage examples
│
├── architecture/                      # System design
│   ├── overview.md                    # High-level architecture
│   ├── rule-engine.md                 # Rule engine internals
│   └── custom-rules.md                # Creating rules
│
├── rules/                             # Rules reference
│   ├── dockerfile-rules.md            # All Dockerfile rules
│   ├── runtime-rules.md               # All runtime rules
│   └── severity-levels.md             # Risk classification
│
└── contributing/                      # Contribution guides
    ├── CONTRIBUTING.md                # Main contributing guide
    ├── development.md                 # Dev environment setup
    ├── testing.md                     # Testing guidelines
    └── code-style.md                  # Coding standards
```

## 🎯 Common Tasks

### Scan a Dockerfile
```bash
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
```
📖 [Full Dockerfile Scanning Guide →](guides/dockerfile-scanning.md)

### Scan Running Containers
```bash
valeris scan --state running
```
📖 [Full Runtime Scanning Guide →](guides/runtime-scanning.md)

### Export to JSON/CSV
```bash
valeris scan --format json --output results.json
valeris scan --format csv --output results.csv
```
📖 [Output Formats Guide →](guides/output-formats.md)

### Filter by Rules
```bash
# Only critical security checks
valeris scan --only privileged_mode,capabilities,secrets_in_env

# Exclude noisy rules
valeris scan --exclude readonly_rootfs,log_driver
```
📖 [Filtering Guide →](guides/filtering.md)

### Add Custom Rule
```yaml
# rules/runtime/docker/my-rule.yaml
id: my_custom_rule
name: "My Custom Detector"
target: docker_runtime
severity: HIGH
match:
  jsonpath: "$.Config.SomeField"
  equals: "bad-value"
message: "Custom issue detected"
```
📖 [Custom Rules Guide →](architecture/custom-rules.md)

## 🔍 Finding Information

### By Topic

**Security:**
- [Dockerfile Security Rules](rules/dockerfile-rules.md#security)
- [Runtime Security Rules](rules/runtime-rules.md#security)
- [Severity Levels](rules/severity-levels.md)

**Configuration:**
- [Environment Variables](guides/configuration.md#environment-variables)
- [Rules Directory](guides/configuration.md#rules-directory)
- [Output Settings](guides/configuration.md#output-settings)

**Integration:**
- [GitHub Actions](guides/ci-cd-integration.md#github-actions)
- [GitLab CI](guides/ci-cd-integration.md#gitlab-ci)
- [Jenkins](guides/ci-cd-integration.md#jenkins)

**Development:**
- [Architecture](architecture/overview.md)
- [Adding Features](contributing/development.md)
- [Writing Tests](contributing/testing.md)

### By Question

**"How do I...?"**
- ...scan a Dockerfile? → [Quick Start](guides/quick-start.md#2-scan-a-dockerfile)
- ...filter results? → [Filtering Guide](guides/filtering.md)
- ...export to JSON? → [Output Formats](guides/output-formats.md#json-export)
- ...add a custom rule? → [Custom Rules](architecture/custom-rules.md)
- ...integrate with CI? → [CI/CD Guide](guides/ci-cd-integration.md)

**"What is...?"**
- ...the architecture? → [Architecture Overview](architecture/overview.md)
- ...a YAML rule? → [Rule Engine](architecture/rule-engine.md)
- ...severity level? → [Severity Levels](rules/severity-levels.md)
- ...JSONPath? → [Rule Engine - JSONPath](architecture/rule-engine.md#jsonpath)

**"Where can I find...?"**
- ...all Dockerfile rules? → [Dockerfile Rules](rules/dockerfile-rules.md)
- ...all runtime rules? → [Runtime Rules](rules/runtime-rules.md)
- ...example scans? → [Examples](guides/examples.md)
- ...contribution guide? → [Contributing](contributing/CONTRIBUTING.md)

## 🆘 Getting Help

### Documentation
1. Check this documentation index
2. Search the specific guide you need
3. Review examples in the guides

### Community Support
- 💬 [GitHub Discussions](https://github.com/rsgbengi/valeris/discussions)
- 🐛 [Issue Tracker](https://github.com/rsgbengi/valeris/issues)
- 📝 [Blog Series](https://www.kayssel.com/series/docker-security/)

### Reporting Issues
1. Check [Troubleshooting Guide](guides/troubleshooting.md)
2. Search existing issues
3. Create new issue with template

## 📝 Contributing to Docs

Found an error? Want to improve documentation?

1. **Quick Fixes** - Open a PR with the change
2. **New Guides** - Discuss in an issue first
3. **Translations** - Contact maintainers

See [Contributing Guide](contributing/CONTRIBUTING.md#-documentation-contributions)

## 📚 External Resources

### Docker Security
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

### Rust & Docker
- [Rust Book](https://doc.rust-lang.org/book/)
- [Docker API Documentation](https://docs.docker.com/engine/api/)
- [Bollard Crate](https://docs.rs/bollard/)

### Learning Resources
- [Valeris Blog Series](https://www.kayssel.com/series/docker-security/)
- [JSONPath Tutorial](https://goessner.net/articles/JsonPath/)
- [Regex Reference](https://docs.rs/regex/)

## 📊 Documentation Status

| Section | Status | Last Updated |
|---------|--------|--------------|
| Quick Start | ✅ Complete | 2025-01-06 |
| Architecture | ✅ Complete | 2025-01-06 |
| Dockerfile Rules | ✅ Complete | 2025-01-06 |
| Runtime Rules | ✅ Complete | 2025-01-06 |
| Contributing | ✅ Complete | 2025-01-06 |
| CI/CD Guide | 🔄 In Progress | - |
| Advanced Topics | 📝 Planned | - |

**Legend:** ✅ Complete | 🔄 In Progress | 📝 Planned

---

**Happy scanning! 🛡️**

For questions or feedback, open an issue or start a discussion on GitHub.
