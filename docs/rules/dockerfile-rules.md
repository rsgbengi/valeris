# Dockerfile Security & Best Practices Rules

This directory contains YAML rules for static analysis of Dockerfiles.

## 📋 Rule Categories

### 1. **latest.yaml** - Reproducibility
- `DF001` - Detects use of mutable tags (`:latest` or no tag)

### 2. **security.yaml** - Basic Security
- `DF002` - Explicit root user
- `DF003` - Sensitive ports exposed (SSH, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch)
- `DF004` - Stage without non-root USER at the end
- `DF005` - Using ADD instead of COPY
- `DF006` - Hardcoded secrets in ENV (passwords, tokens, api keys)
- `DF007` - Missing .dockerignore with COPY .
- `DF008` - Shell form in RUN

### 3. **apt-cache.yaml** - APT Package Management
- `DF101` - apt-get install without cache cleanup
- `DF102` - apt-get install without apt-get update
- `DF103` - apt-get install without -y flag
- `DF104` - Using `apt` instead of `apt-get`

### 4. **curl-wget.yaml** - Secure Downloads
- `DF201` - curl/wget without checksum verification
- `DF202` - curl with insecure flag (-k/--insecure)
- `DF203` - wget with --no-check-certificate
- `DF204` - HTTP downloads instead of HTTPS

### 5. **pip-npm.yaml** - Python/Node Package Managers
- `DF301` - pip install without requirements.txt
- `DF302` - npm install instead of npm ci
- `DF303` - pip install without --no-cache-dir
- `DF304` - npm install -g (global)
- `DF305` - pip install as root without --user

### 6. **workdir-healthcheck.yaml** - Dockerfile Structure
- `DF401` - Using `cd` instead of WORKDIR
- `DF402` - Missing HEALTHCHECK
- `DF403` - Relative paths in COPY
- `DF404` - WORKDIR with relative path

### 7. **multistage.yaml** - Multi-stage Builds
- `DF501` - Build tools in final image
- `DF502` - FROM without alias (AS)
- `DF503` - Git installed in final image
- `DF504` - npm install without --production

### 8. **shell-vulnerabilities.yaml** - Shell Vulnerabilities
- `DF601` - Using sudo (unnecessary)
- `DF602` - Shell variable expansion
- `DF603` - Using eval/exec
- `DF604` - chown with variables
- `DF605` - chmod 777 (world-writable permissions)
- `DF606` - setuid/setgid bits

### 9. **dangerous-commands.yaml** - Anti-patterns
- `DF801` - sshd in container
- `DF802` - systemd/init systems
- `DF803` - sleep infinity in CMD
- `DF804` - cron in foreground
- `DF805` - Installing unnecessary tools (vim, nano, netcat)
- `DF806` - dist-upgrade
- `DF807` - Removing package manager

### 10. **image-metadata.yaml** - Metadata
- `DF701` - Missing LABEL maintainer
- `DF702` - Hardcoded VERSION (should use ARG)
- `DF703` - Multiple LABELs (can be combined)

## 🎯 Severity Levels

- **CRITICAL** (5 rules): Serious security vulnerabilities
- **HIGH** (2 rules): Important security issues
- **MEDIUM** (9 rules): Moderate problems
- **LOW** (18 rules): Best practices and optimizations
- **INFO** (3 rules): Informational recommendations

**Total: 37 rules**

## 📊 Usage

```bash
# Basic scan
valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
valeris df -p ./Dockerfile -r ./rules/dockerfile  # Short alias

# Filter by severity
valeris df -p ./Dockerfile -r ./rules/dockerfile --severity high
valeris df -p ./Dockerfile -r ./rules/dockerfile --min-severity medium

# Run only specific rules
valeris df -p ./Dockerfile -r ./rules/dockerfile --only DF001,DF006
valeris df -p ./Dockerfile -r ./rules/dockerfile --only DF002,DF004

# Exclude specific rules
valeris df -p ./Dockerfile -r ./rules/dockerfile --exclude DF008,DF005

# CI/CD integration
valeris df -p ./Dockerfile -r ./rules/dockerfile --fail-on high
valeris df -p ./Dockerfile -r ./rules/dockerfile --quiet --fail-on medium

# Export formats
valeris df -p ./Dockerfile -r ./rules/dockerfile --format json --output results.json
valeris df -p ./Dockerfile -r ./rules/dockerfile --format csv --output report.csv
```

## 🔧 Secure Dockerfile Example

```dockerfile
# ✅ GOOD: Multi-stage build with minimal image
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:18-alpine
WORKDIR /app
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --chown=nodejs:nodejs . .
USER nodejs
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node healthcheck.js
CMD ["node", "server.js"]
```

## 📝 Notes

- Rules are automatically loaded from this directory
- You can disable specific rules by editing or deleting files
- Regexes use Rust syntax (`regex` crate)
- Supported scopes: `instruction`, `stage`, `file`
