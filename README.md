# 🐉 Valeris

[![Rust Version](https://img.shields.io/badge/Rust-1.71%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#-license)

<p align="center">
  <img src="logo.webp" alt="Valeris logo" width="200"/>
</p>

> **Valeris** is a lightning-fast security scanner for **Docker containers and Dockerfiles**.
> Rules are defined in plain **YAML** and loaded at runtime by a blazingly fast Rust engine.
> _⚠ Project under active development – rule-authoring guide & stable API will arrive after v0.2._
> You can follow the development at <https://www.kayssel.com/series/docker-security/>

---

## 🎯 Why Valeris?

|   |   |
|---|---|
| **Dual-mode scanning** | Runtime container inspection + static Dockerfile analysis |
| **Declarative rules** | Add or tweak detectors by editing a YAML file; no re-compile required |
| **Native speed** | 6-8 MB static binary, async I/O with Tokio & Bollard |
| **Professional output** | Colored tables, JSON, CSV exports with structured logging |
| **Learning in public** | Every commit documents the Rust concepts behind the rewrite |

---

## ✨ Current Features

### Runtime Scanning 🔍
- ✅ Inspects live containers via Docker API
- ✅ Detects: privileged mode, host networking/IPC, dangerous capabilities
- ✅ Checks: exposed ports, PID limits, root user, user namespaces
- ✅ Filter by container state (`--state running`)
- ✅ Filter by container name or ID (`--container nginx`)
- ✅ Filter by severity level (`--severity high`, `--min-severity medium`)
- ✅ Selective scanning with `--only` and `--exclude`
- ✅ CI/CD integration with `--fail-on` and `--quiet` modes
- ✅ Command aliases for faster workflow (`scan` → `s`, `list-plugins` → `ls`)

### Dockerfile Scanning 📄
- ✅ Static analysis of Dockerfiles
- ✅ Multi-scope rules: instruction-level, stage-level, file-level
- ✅ Detects: latest tags, root users, missing .dockerignore
- ✅ Validates: shell form vs exec form, security best practices

### Export & Reporting 📊
- ✅ Beautiful colored terminal output with tables
- ✅ JSON export for CI/CD integration
- ✅ CSV export for spreadsheet analysis
- ✅ Structured logging with configurable verbosity (`RUST_LOG`)

### Architecture 🏗️
- ✅ Unified output system (printer + exporters)
- ✅ Centralized configuration module
- ✅ Comprehensive error handling with context
- ✅ 92 passing tests with snapshot testing
- ✅ Zero clippy warnings

---

## 🚀 Installation

> **Prerequisites**
> • Docker daemon running locally
> • Rust 1.71+ (1.81+ recommended)
> • Linux or macOS<sup>†</sup>

```bash
# Install from Git
cargo install --git https://github.com/rsgbengi/valeris.git --locked

# Or build locally
git clone https://github.com/rsgbengi/valeris.git
cd valeris
cargo build --release
sudo mv target/release/valeris /usr/local/bin
```

<sup>†</sup> Windows support will land after 0.2.

---

## ⚡ Quick Start

### Runtime Container Scanning

```bash
# Scan all running containers with the default rule set
valeris scan
# Or use the short alias
valeris s

# Filter by container name or ID
valeris scan --container nginx
valeris scan -c redis,postgres
valeris scan --container web-app-1

# Filter by container state
valeris scan --state running
valeris scan --state running,paused

# Run only specific detectors
valeris scan --only exposed_ports,capabilities

# Exclude noisy checks
valeris scan --exclude readonly_rootfs

# Filter by severity
valeris scan --severity high
valeris scan --min-severity medium

# CI/CD integration - fail on critical findings
valeris scan --fail-on high
valeris scan --quiet --fail-on medium  # Quiet mode for scripts

# Combine filters for precise targeting
valeris scan --state running --container nginx --min-severity high

# Export results to JSON
valeris scan --format json --output results.json

# Export to CSV
valeris scan --format csv --output findings.csv
```

### Dockerfile Scanning

```bash
# Scan a Dockerfile
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
# Or use the short alias
valeris df -p ./Dockerfile -r ./rules/dockerfile

# Export Dockerfile scan to JSON
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile --format json --output scan.json

# Export to CSV
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile --format csv
```

### Advanced Usage

```bash
# List all available detectors
valeris list-plugins
# Or use the short alias
valeris ls

# Filter plugins by target
valeris list-plugins --target docker

# Enable verbose logging
RUST_LOG=debug valeris scan

# Info-level logging only
RUST_LOG=info valeris scan

# Custom rules directory
VALERIS_RULES_DIR=/path/to/rules valeris scan
```

---

## 📦 Example Reports

### Runtime Container Scan

```bash
$ valeris scan

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🐳 Container: my-app
   Image: nginx:latest
   Status: Running
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ⚠️  5 issues found: 2 critical, 2 medium, 1 low

┌──────────┬────────────────┬─────────────────────────────────────────────────┐
│ Severity │ Rule ID        │ Description                                      │
╞══════════╪════════════════╪═════════════════════════════════════════════════╡
│ CRITICAL │ root_user      │ Container is running as root                     │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ CRITICAL │ capabilities   │ Container has dangerous capabilities: SYS_ADMIN  │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ MEDIUM   │ memory_limit   │ Memory limit not set                             │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ MEDIUM   │ exposed_ports  │ Container exposes port 22 (SSH)                  │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ LOW      │ readonly_rootfs│ Root filesystem is writable                     │
└──────────┴────────────────┴─────────────────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Dockerfile Scan

```bash
$ valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 Scanning Dockerfile: Dockerfile
   Path: ./Dockerfile
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ⚠️  3 issues found: 1 critical, 1 medium, 1 low

┌──────────┬───────┬──────┬────────────────────────────────────────────────────┐
│ Severity │ ID    │ Line │ Description                                        │
╞══════════╪═══════╪══════╪════════════════════════════════════════════════════╡
│ MEDIUM   │ DF001 │ 1    │ Stage 0: Base image uses mutable tag (latest)      │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ CRITICAL │ DF002 │ 5    │ Stage 0: Container runs as root user               │
├╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ LOW      │ DF008 │ 3    │ Stage 0: RUN uses shell form                       │
└──────────┴───────┴──────┴────────────────────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Legend:** `CRITICAL` High risk | `MEDIUM` Medium risk | `LOW` Low risk | `INFO` Informational

---

## 🔌 List Available Detectors

```bash
$ valeris list-plugins

Available YAML detectors:
- [root_user] Root User docker_runtime
- [privileged_mode] Privileged Mode docker_runtime
- [network_mode] Host Network Mode docker_runtime
- [mounts] Sensitive Mounts docker_runtime
- [exposed_ports] Exposed Ports docker_runtime
- [capabilities] Linux Capabilities docker_runtime
- [pid_mode] PID Mode docker_runtime
- [ipc_mode] IPC Mode docker_runtime
- [uts_mode] UTS Mode docker_runtime
- [user_namespace] User Namespace docker_runtime
- [readonly_rootfs] Read-only Root FS docker_runtime
- [resource_memory] Memory Limits docker_runtime
- [resource_cpu] CPU Limits docker_runtime
- [pid_limits] PID Limits docker_runtime
- [restart_policy] Restart Policy docker_runtime
- [security_opt] Security Options docker_runtime
- [secrets_in_env] Secrets in Environment docker_runtime
```

---

## 🏗️ Architecture

```
src/
├── cli.rs              # Command-line interface (clap)
├── config.rs           # Centralized configuration
├── detectors/
│   ├── runtime/        # Container runtime scanning
│   │   ├── scanner.rs  # Docker API integration
│   │   └── yaml_rules.rs # YAML rule engine
│   └── dockerfile/     # Static Dockerfile analysis
│       ├── scanner.rs  # Dockerfile parser integration
│       ├── yaml_rules.rs # Rule definitions
│       └── matcher.rs  # Rule matching logic
├── docker/
│   └── model.rs        # Data models (Finding, RiskLevel)
├── output/
│   ├── printer.rs      # Unified console output
│   └── exporters.rs    # JSON/CSV export
└── rules.rs            # Rule download & management
```

### Key Components

- **YAML Rule Engine**: JSONPath-based matching with regex/equals/parts support
- **Unified Output**: Single printer/exporter for all scan types
- **Configuration**: Centralized settings with environment variable override
- **Async Runtime**: Tokio for concurrent Docker API calls
- **Error Handling**: Comprehensive context with `anyhow`

---

## 🗺️ Roadmap

| Version | Scope | Status |
|---------|-------|--------|
| **0.1 α – Core Engine** | Runtime + Dockerfile scanning | ✅ Complete |
| **0.2 β – CI-Ready** | Integration tests, coverage, stability | 🛠 In Progress |
| **0.3 – Interactive UX** | TUI dashboard, rule authoring guide | ⬜ Planned |
| **0.4 – K8s Static** | Scan Helm/Kustomize manifests | ⬜ Planned |
| **0.5 – K8s Runtime** | Live cluster scanning, CIS benchmarks | ⬜ Planned |
| **1.0 – LTS** | Stable API, signed binaries | ⬜ Planned |

**Legend:** ✅ Done | 🛠 WIP | ⬜ Planned

---

## 📝 Configuration

### Configuration File

Valeris supports persistent configuration via TOML files. Create a config file to avoid repeating common flags:

```bash
# Check config status
valeris config

# Create config file
mkdir -p ~/.config/valeris
cp valeris.toml.example ~/.config/valeris/config.toml
vi ~/.config/valeris/config.toml
```

**Config file locations** (checked in order):
1. `$VALERIS_CONFIG_FILE` (environment variable)
2. `~/.config/valeris/config.toml` (XDG config dir)
3. `~/.valeris.toml` (home directory)

**Example configuration:**
```toml
[scan]
default_state = ["running"]
exclude = ["readonly_rootfs", "log_driver"]
min_severity = "medium"

[output]
format = "table"
colors = true
```

### Environment Variables

- `VALERIS_CONFIG_FILE` - Override config file location
- `VALERIS_RULES_DIR` - Override default rules directory
- `RUST_LOG` - Set logging level (`debug`, `info`, `warn`, `error`)

### Default Locations

- **Config**: `~/.config/valeris/config.toml`
- **Rules**: `$XDG_DATA_HOME/valeris/detectors` or `~/.local/share/valeris/detectors`
- **Runtime rules**: `detectors/runtime/docker/*.yaml`
- **Dockerfile rules**: `detectors/dockerfile/*.yaml`

---

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Update test snapshots
cargo insta review

# Run specific test
cargo test test_name

# Clippy lints
cargo clippy --all-targets --all-features
```

---

## 🤝 Contributing

Valeris is in **public-learning alpha**.
Issues & PRs are welcome! Check out the [development blog](https://www.kayssel.com/series/docker-security/) for context.

### Development Setup

```bash
git clone https://github.com/rsgbengi/valeris.git
cd valeris
cargo build
cargo test
```

---

## 🔒 License

MIT © 2025 Ruben Santos Garcia – see [LICENSE](./LICENSE.md).

---

## 🧠 Inspiration

Inspired by Docker Bench, Dockle, and RustScan — merged into a quest for **clearer, faster, more focused** DevSecOps tooling.

_Made with ❤️ and structured logging while learning Rust._

---

## 📚 Learn More

- **Blog Series**: [Docker Security with Valeris](https://www.kayssel.com/series/docker-security/)
- **Documentation**: See [CLAUDE.md](./CLAUDE.md) for architecture details
- **Rules**: Check [rules/](./rules/) for example YAML detectors
