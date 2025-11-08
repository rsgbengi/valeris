# Valeris Documentation

Welcome to the Valeris documentation! This guide will help you understand, use, and contribute to Valeris.

## 📚 Table of Contents

### Getting Started
- [Quick Start Guide](guides/quick-start.md) - Get up and running in 5 minutes
- [CLI Reference](CLI.md) - Complete command-line interface documentation
- [Configuration Guide](CONFIGURATION.md) - Configuration file and environment variables

### Integration
- [CI/CD Integration](CI-CD-INTEGRATION.md) - Integrate Valeris into your pipelines

### Architecture
- [Architecture Overview](architecture/overview.md) - System design and components

### Rules Reference
- [Dockerfile Rules](rules/dockerfile-rules.md) - All 37 Dockerfile security rules
- [Runtime Rules](rules/runtime-rules.md) - All 36 container runtime rules

### Contributing
- [Contributing Guide](contributing/CONTRIBUTING.md) - How to contribute

## 🚀 Quick Links

### For Users
- **New to Valeris?** → [Quick Start Guide](guides/quick-start.md)
- **CLI commands?** → [CLI Reference](CLI.md)
- **Configuration?** → [Configuration Guide](CONFIGURATION.md)
- **CI/CD integration?** → [CI/CD Integration](CI-CD-INTEGRATION.md)

### For Developers
- **Architecture?** → [Overview](architecture/overview.md)
- **Contribute?** → [Contributing](contributing/CONTRIBUTING.md)

### Reference
- **Dockerfile rules?** → [Dockerfile Rules](rules/dockerfile-rules.md)
- **Runtime rules?** → [Runtime Rules](rules/runtime-rules.md)

## 📖 Documentation Structure

```
docs/
├── README.md                          # This file (documentation index)
│
├── CLI.md                             # Complete CLI reference
├── CONFIGURATION.md                   # Configuration guide
├── CI-CD-INTEGRATION.md               # CI/CD integration guide
│
├── guides/                            # User guides
│   └── quick-start.md                 # 5-minute getting started
│
├── architecture/                      # System design
│   └── overview.md                    # High-level architecture
│
├── rules/                             # Rules reference
│   ├── dockerfile-rules.md            # All Dockerfile rules (37 rules)
│   └── runtime-rules.md               # All runtime rules (36 rules)
│
└── contributing/                      # Contribution guides
    └── CONTRIBUTING.md                # Main contributing guide
```

## 🎯 Common Tasks

### Scan a Dockerfile
```bash
# Basic scan
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
# With short alias
valeris df -p ./Dockerfile -r ./rules/dockerfile

# With severity filtering
valeris df -p ./Dockerfile -r ./rules/dockerfile --min-severity high

# CI/CD integration
valeris df -p ./Dockerfile -r ./rules/dockerfile --fail-on high --quiet
```
📖 See [Dockerfile Rules](rules/dockerfile-rules.md) for all available rules

### Scan Running Containers
```bash
# Basic scan
valeris scan --state running
# With short alias
valeris s --state running

# With severity filtering
valeris scan --state running --min-severity medium

# CI/CD integration
valeris scan --state running --fail-on high --quiet
```
📖 See [Runtime Rules](rules/runtime-rules.md) for all available rules

### Export to JSON/CSV
```bash
valeris scan --format json --output results.json
valeris scan --format csv --output results.csv
valeris df -p ./Dockerfile -r ./rules/dockerfile -f json -o report.json
```

### Filter by Rules
```bash
# Runtime scanner - only critical security checks
valeris scan --only privileged_mode,capabilities,secrets_in_env

# Runtime scanner - exclude noisy rules
valeris scan --exclude readonly_rootfs,log_driver

# Dockerfile scanner - only specific rules
valeris df -p ./Dockerfile -r ./rules/dockerfile --only DF001,DF002,DF006

# Dockerfile scanner - exclude specific rules
valeris df -p ./Dockerfile -r ./rules/dockerfile --exclude DF703,DF702
```

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
📖 See [Contributing Guide](contributing/CONTRIBUTING.md#-adding-security-rules) for more details

## 🔍 Finding Information

### By Topic

**Security:**
- [Dockerfile Security Rules](rules/dockerfile-rules.md)
- [Runtime Security Rules](rules/runtime-rules.md)

**Architecture:**
- [System Overview](architecture/overview.md)
- [Rule Engine](architecture/overview.md#-core-components)
- [Data Flow](architecture/overview.md#-execution-flow)

**Development:**
- [Architecture](architecture/overview.md)
- [Contributing](contributing/CONTRIBUTING.md)

### By Question

**"How do I...?"**
- ...scan a Dockerfile? → [Quick Start - Scan Dockerfile](guides/quick-start.md#2-scan-a-dockerfile)
- ...scan containers? → [Quick Start - Scan Containers](guides/quick-start.md#1-scan-running-containers)
- ...filter results? → [Quick Start - Filtering](guides/quick-start.md#filtering-results)
- ...filter by severity? → [Quick Start - By Severity](guides/quick-start.md#by-severity)
- ...export to JSON? → [Quick Start - Export](guides/quick-start.md#3-export-results)
- ...use in CI/CD? → [CI/CD Integration](CI-CD-INTEGRATION.md)
- ...configure Valeris? → [Configuration Guide](CONFIGURATION.md)
- ...use CLI commands? → [CLI Reference](CLI.md)
- ...add a custom rule? → [Contributing - Adding Rules](contributing/CONTRIBUTING.md#-adding-security-rules)

**"What is...?"**
- ...the architecture? → [Architecture Overview](architecture/overview.md)
- ...a YAML rule? → [Architecture - Rule Engine](architecture/overview.md#3-rule-engine-srcdetectorsruntimeyaml_rulesrs)
- ...JSONPath? → [Runtime Rules - JSONPath Examples](rules/runtime-rules.md#-jsonpath-examples)
- ...the --fail-on flag? → [CI/CD Integration - fail-on Behavior](CI-CD-INTEGRATION.md#fail-on-behavior)
- ...severity filtering? → [CI/CD Integration - Severity Filtering](CI-CD-INTEGRATION.md#severity-filtering)

**"Where can I find...?"**
- ...all CLI commands? → [CLI Reference](CLI.md)
- ...all Dockerfile rules? → [Dockerfile Rules](rules/dockerfile-rules.md)
- ...all runtime rules? → [Runtime Rules](rules/runtime-rules.md)
- ...CI/CD examples? → [CI/CD Integration](CI-CD-INTEGRATION.md#pipeline-examples)
- ...configuration options? → [Configuration Guide](CONFIGURATION.md)
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
1. Search existing issues
2. Create new issue with template from [Contributing Guide](contributing/CONTRIBUTING.md#-reporting-bugs)

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
| Quick Start | ✅ Complete | 2025-01-10 |
| CLI Reference | ✅ Complete | 2025-01-10 |
| Configuration Guide | ✅ Complete | 2025-01-06 |
| CI/CD Integration | ✅ Complete | 2025-01-10 |
| Architecture | ✅ Complete | 2025-01-06 |
| Dockerfile Rules | ✅ Complete | 2025-01-10 |
| Runtime Rules | ✅ Complete | 2025-01-06 |
| Contributing | ✅ Complete | 2025-01-06 |

**Legend:** ✅ Complete

### Recent Updates (2025-01-10)
- ✨ **Dockerfile Scanner** - Feature complete with severity filtering, fail-on, only/exclude
- 📚 **CLI Reference** - Complete documentation of all commands and options
- 🚀 **CI/CD Integration** - Comprehensive guide with pipeline examples
- 📖 **Quick Start** - Updated with Dockerfile scanner features
- 📋 **Dockerfile Rules** - Updated with filtering examples

---

**Happy scanning! 🛡️**

For questions or feedback, open an issue or start a discussion on GitHub.
