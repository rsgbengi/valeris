# 🐉 Valeris

[![Rust Version](https://img.shields.io/badge/Rust-1.71%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#\-license)

<p align="center">
  <img src="logo.webp" alt="Valeris logo" width="200"/>
</p>

> **Valeris** is a lightning-fast security scanner for **running Docker containers**.  
> Rules are defined in plain **YAML** and loaded at runtime by a small Rust engine.  
> _⚠ Project under active development – rule-authoring guide & stable API will arrive after v0.2._
> You can follow the development in <https://www.kayssel.com/series/docker-security/>

---

## 🎯 Why Valeris?

|   |   |
|---|---|
| **Runtime first** | Detect mis-configurations _inside_ containers (privileged mode, exposed ports, dangerous capabilities …) |
| **Declarative rules** | Add or tweak detectors by editing a YAML file; no re-compile required. |
| **Native speed** | 6-8 MB static binary, async I/O with Tokio & Bollard. |
| **Learning in public** | Every commit documents the Rust concepts behind the rewrite from “plugins” → “YAML rules”. |

---

## ✨ Current features

| Category | Implemented today |
|----------|-------------------|
| 🔍 Runtime scan | Inspects every live container, no image rebuild required |
| 📑 YAML detectors | Enable / exclude with `--only` and `--exclude` |
| ⚠️ Built-in checks | Privileged mode • Host networking/IPC • Dangerous caps • Exposed ports • No PIDs limit • Root user • … |
| ⚡ Fast & portable | Single Rust binary; only dependency is the Docker socket |

_Planned → JSON/CSV reporters · TUI dashboard · Kubernetes support · Signed detector bundles._

---

## 🚀 Installation

> **Prerequisites**  
> • Docker daemon running locally  
> • Rust 1.71 + (1.81 + recommended)  
> • Linux or macOS<sup>†</sup>

```bash
cargo install --git https://github.com/rsgbengi/valeris.git --locked

# or build locally
git clone https://github.com/rsgbengi/valeris.git
cd valeris
cargo build --release
sudo mv target/release/valeris /usr/local/bin
```

<sup>†</sup> Windows support will land after 0.2.

---

## ⚡ Quick start

```bash
# Scan all running containers with the default rule set
valeris scan

# Run only two detectors
valeris scan --only exposed_ports,capabilities

# Exclude noisy checks
valeris scan --exclude readonly_rootfs

# Filter containers by Docker state
valeris scan --state running
```


## 🔌 List available detectors

```bash
valeris list-plugins

- [root_user] Root User (YAML) docker_runtime
- [privileged_mode] Privileged Mode (YAML) docker_runtime
- [network] Host Network Mode Checker docker_runtime
- [mounts] Sensitive Mounts Checker docker_runtime
- [exposed_ports] Exposed Ports Analyzer docker_runtime
- [capabilities] Linux Capabilities Checker docker_runtime
```

## 📦 Example Report

```bash
valeris scan

🔍 Container: root-user-test-2
   └─ Image: debian:stable-slim
   └─ Status: Exited
 [!!]  root_user: Container is running as root
 [!]   resource_limits_memory: Memory limit not set
 [!]   resource_limits_cpu: CPU limit not set
 [!!]  user_namespace: Container is running without user namespaces
```
Legend  `[!!]` Critical `[!]` Medium  `[.]` Low `[i]` Informational


## 🗺 Roadmap

| Version | Scope | Key tasks |
|---------|-------|-----------|
| **0.1 α – Core YAML engine** | Runtime scanner + YAML detectors | ✅ CLI (\`clap\`) · ✅ Recursive rule loader · ✅ \`--only\` / \`--exclude\` |
| **0.2 β – CI-ready** | Reliability | 🛠 Integration tests with `insta` · 🛠 Coverage in CI · ⬜ JSON/CSV reporters |
| **0.3 – Interactive UX** | Local debugging | ⬜ Optional TUI (`ratatui`) · ⬜ Rule authoring guide |
| **0.4 – K8s Static** | Scan manifests | ⬜ Helm / Kustomize support |
| **0.5 – K8s Runtime** | Live clusters | ⬜ Pod runtime checks · ⬜ CIS profile |
| **1.0 – LTS** | Stable API | ⬜ Freeze rule schema · ⬜ Signed binaries & SBOM |

Legend  ✅ Done 🛠 WIP ⬜ Planned

---

## 🤝 Contributing

Valeris is in **public-learning alpha**.  
Issues & PRs will open once v0.2 lands; meanwhile feel free to fork or ping me by email.

---

## 🔒 License

MIT © 2025 Ruben Santos Garcia – see [LICENSE](./LICENSE.md).

---

### 🧠 Inspiration

Docker Bench • Dockle • RustScan — all merged into a quest for **clearer, faster, more focused** DevSecOps tooling.

_Made with ❤️ & copious \`println!("{:?}", …)\` while learning Rust._

