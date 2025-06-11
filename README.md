# 🐉 Valeris

[![Rust Version](https://img.shields.io/badge/Rust-1.71%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#-license)

<p align="center">
  <img src="logo.webp" alt="Valeris logo" width="200"/>
</p>

> **Valeris** is a lightning-fast security scanner for **running Docker containers** – built as a public Rust learning journey.

## 🎯 Why Valeris?

1. **Runtime first** – catch misconfigurations _inside_ containers (privileged mode, risky mounts, leaked secrets).  
2. **Plugins, not monolith** – enable or write detectors in minutes.  
3. **Native speed** – single 6‑8 MB binary, async inspection with Tokio & Bollard.  
4. **Learning in public** – every commit and blog post shows the Rust concepts involved.

Follow the behind‑the‑scenes series here → <https://www.kayssel.com/series/docker-security/>

## ✨ Features

| Category | What it does today |
|----------|-------------------|
| 🔍 **Runtime scanning** | Inspects every live container without rebuilding images. |
| 🧩 **Plugin system** | Toggle detectors with `--only` / `--exclude`. |
| ⚠️ **Misconfigs detected** | Root users • Privileged mode • Sensitive env‑vars • `/var/run/docker.sock` mounts • Dangerous caps • Exposed ports • Missing restart policies |
| ⚡ **Fast & portable** | Rust binary, no external deps beyond the Docker socket. |

Planned → JSON/CSV reports · TUI dashboard · Kubernetes support · Signed plugins.

## 🚀 Installation

> **Prerequisites**  
> • Docker daemon running locally  
> • Rust 1.71 + (1.81 + recommended)  
> • Linux or macOS<sup>†</sup>

```bash
cargo install --git https://github.com/rsgbengi/valeris.git --locked
# or build locally
git clone https://github.com/rsgbengi/valeris.git && cd valeris
cargo build --release
sudo mv target/release/valeris /usr/local/bin
```

<sup>†</sup> Windows support will land after 0.2.


## ⚡ Quick Start

```bash
# Scan all running containers
valeris scan

# Only run a couple of detectors
valeris scan --only root_user,secrets_in_env

# Exclude noisy checks
valeris scan --exclude mounts_rw,privileged_mode
```

## 📦 Example Output

```
🔍 Container: kraken-mixed  (alpine:latest)
 ├── [!!]  User: running as root                (fix: use --user or non-root base image)
 ├── [!!]  Mount: /var/run/docker.sock → /var/run/docker.sock
 ├── [i]   Mount: /home/rsgbengi → /app
 └── [i]   RestartPolicy: 'no' — container won’t auto-restart
```

Legend  `[!!]` Critical  `[i]` Info

## 🗺 Roadmap

| Version | Goal | Key tasks |
|---------|------|-----------|
| **0.1 α – Core Scanner** | Early adopters | ✅ CLI `clap` • ✅ Docker plugins • ✅ `--only/--exclude` • ✅ Base detectors |
| **0.2 β – CI‑ready** | Reliability | ⬜ Unit & integration tests • ⬜ Coverage in CI • ⬜ JSON/CSV reporters • ⬜ Colored severity output |
| **0.3 – Interactive UX** | Local debugging | ⬜ Optional TUI (`ratatui`) • ⬜ Plugin SDK docs |
| **0.4 – K8s Static** | Scan manifests | ⬜ YAML/Helm/Kustomize via `kubectl` |
| **0.5 – K8s Runtime** | Live clusters | ⬜ Namespace scan • ⬜ CIS profile |
| **1.0 – LTS** | Stable API | ⬜ Freeze plugin contract • ⬜ Signed binaries & SBOM • ⬜ Complete manual |

Legend  ✅ Done 🛠 WIP ⬜ Planned

## 🤝 Contributing

> 🧪 **Experiment phase** – Issues & PRs will open once 1.0 is tagged.  
> Until then, feel free to fork or drop questions by email.


## 🔒 License

MIT © 2025 Ruben Santos Garcia – see [LICENSE](./LICENSE.md).

## 🧠 Inspiration

Docker Bench • Dockle • RustScan • the pursuit of **clearer, faster, more focused** DevSecOps tools.

_“Made with ❤️ & copious `println!("{:?}", …)` while learning Rust.”_
