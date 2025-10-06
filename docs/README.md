# Valeris Documentation

Welcome to the Valeris documentation! This guide will help you understand, use, and contribute to Valeris.

## 📚 Table of Contents

### Getting Started
- [Quick Start Guide](guides/quick-start.md) - Get up and running in 5 minutes

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

### For Developers
- **Architecture?** → [Overview](architecture/overview.md)
- **Contribute?** → [Contributing](contributing/CONTRIBUTING.md)

### Reference
- **Dockerfile rules?** → [Dockerfile Rules](rules/dockerfile-rules.md)
- **Runtime rules?** → [Runtime Rules](rules/runtime-rules.md)

## 📖 Documentation Structure

```
docs/
├── README.md                          # This file
│
├── guides/                            # User guides
│   └── quick-start.md                 # 5-minute getting started
│
├── architecture/                      # System design
│   └── overview.md                    # High-level architecture
│
├── rules/                             # Rules reference
│   ├── dockerfile-rules.md            # All Dockerfile rules
│   └── runtime-rules.md               # All runtime rules
│
└── contributing/                      # Contribution guides
    └── CONTRIBUTING.md                # Main contributing guide
```

## 🎯 Common Tasks

### Scan a Dockerfile
```bash
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
```

### Scan Running Containers
```bash
valeris scan --state running
```

### Export to JSON/CSV
```bash
valeris scan --format json --output results.json
valeris scan --format csv --output results.csv
```

### Filter by Rules
```bash
# Only critical security checks
valeris scan --only privileged_mode,capabilities,secrets_in_env

# Exclude noisy rules
valeris scan --exclude readonly_rootfs,log_driver
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
- ...export to JSON? → [Quick Start - Export](guides/quick-start.md#3-export-results)
- ...add a custom rule? → [Contributing - Adding Rules](contributing/CONTRIBUTING.md#-adding-security-rules)

**"What is...?"**
- ...the architecture? → [Architecture Overview](architecture/overview.md)
- ...a YAML rule? → [Architecture - Rule Engine](architecture/overview.md#3-rule-engine-srcdetectorsruntimeyaml_rulesrs)
- ...JSONPath? → [Runtime Rules - JSONPath Examples](rules/runtime-rules.md#-jsonpath-examples)

**"Where can I find...?"**
- ...all Dockerfile rules? → [Dockerfile Rules](rules/dockerfile-rules.md)
- ...all runtime rules? → [Runtime Rules](rules/runtime-rules.md)
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
| Quick Start | ✅ Complete | 2025-01-06 |
| Architecture | ✅ Complete | 2025-01-06 |
| Dockerfile Rules | ✅ Complete | 2025-01-06 |
| Runtime Rules | ✅ Complete | 2025-01-06 |
| Contributing | ✅ Complete | 2025-01-06 |

**Legend:** ✅ Complete

---

**Happy scanning! 🛡️**

For questions or feedback, open an issue or start a discussion on GitHub.
