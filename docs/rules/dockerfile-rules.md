# Dockerfile Security & Best Practices Rules

Este directorio contiene reglas YAML para análisis estático de Dockerfiles.

## 📋 Categorías de Reglas

### 1. **latest.yaml** - Reproducibilidad
- `DF001` - Detecta uso de tags mutables (`:latest` o sin tag)

### 2. **security.yaml** - Seguridad Básica
- `DF002` - Usuario root explícito
- `DF003` - Puertos sensibles expuestos (SSH, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch)
- `DF004` - Stage sin USER no-root al final
- `DF005` - Uso de ADD en lugar de COPY
- `DF006` - Secretos hardcodeados en ENV (passwords, tokens, api keys)
- `DF007` - Missing .dockerignore con COPY .
- `DF008` - Shell form en RUN

### 3. **apt-cache.yaml** - Gestión de Paquetes APT
- `DF101` - apt-get install sin limpiar cache
- `DF102` - apt-get install sin apt-get update
- `DF103` - apt-get install sin flag -y
- `DF104` - Uso de `apt` en lugar de `apt-get`

### 4. **curl-wget.yaml** - Descargas Seguras
- `DF201` - curl/wget sin verificación de checksum
- `DF202` - curl con flag inseguro (-k/--insecure)
- `DF203` - wget con --no-check-certificate
- `DF204` - Descargas HTTP en lugar de HTTPS

### 5. **pip-npm.yaml** - Gestores de Paquetes Python/Node
- `DF301` - pip install sin requirements.txt
- `DF302` - npm install en lugar de npm ci
- `DF303` - pip install sin --no-cache-dir
- `DF304` - npm install -g (global)
- `DF305` - pip install como root sin --user

### 6. **workdir-healthcheck.yaml** - Estructura del Dockerfile
- `DF401` - Uso de `cd` en lugar de WORKDIR
- `DF402` - Missing HEALTHCHECK
- `DF403` - Paths relativos en COPY
- `DF404` - WORKDIR con path relativo

### 7. **multistage.yaml** - Multi-stage Builds
- `DF501` - Build tools en imagen final
- `DF502` - FROM sin alias (AS)
- `DF503` - Git instalado en imagen final
- `DF504` - npm install sin --production

### 8. **shell-vulnerabilities.yaml** - Vulnerabilidades Shell
- `DF601` - Uso de sudo (innecesario)
- `DF602` - Expansión de variables shell
- `DF603` - Uso de eval/exec
- `DF604` - chown con variables
- `DF605` - chmod 777 (permisos world-writable)
- `DF606` - setuid/setgid bits

### 9. **dangerous-commands.yaml** - Anti-patrones
- `DF801` - sshd en contenedor
- `DF802` - systemd/init systems
- `DF803` - sleep infinity en CMD
- `DF804` - cron en foreground
- `DF805` - Instalación de herramientas innecesarias (vim, nano, netcat)
- `DF806` - dist-upgrade
- `DF807` - Eliminación del package manager

### 10. **image-metadata.yaml** - Metadatos
- `DF701` - Missing LABEL maintainer
- `DF702` - VERSION hardcoded (debería usar ARG)
- `DF703` - Múltiples LABEL (se pueden combinar)

## 🎯 Niveles de Severidad

- **CRITICAL** (5 reglas): Vulnerabilidades graves de seguridad
- **HIGH** (2 reglas): Problemas importantes de seguridad
- **MEDIUM** (9 reglas): Problemas moderados
- **LOW** (18 reglas): Best practices y optimizaciones
- **INFO** (3 reglas): Recomendaciones informativas

**Total: 37 reglas**

## 📊 Uso

```bash
# Escanear un Dockerfile
cargo run -- docker-file --path ./Dockerfile --rules ./rules/dockerfile

# Formato JSON
cargo run -- docker-file --path ./Dockerfile --rules ./rules/dockerfile --format json

# Guardar resultados
cargo run -- docker-file --path ./Dockerfile --rules ./rules/dockerfile --format json --output results.json
```

## 🔧 Ejemplos de Dockerfile Seguro

```dockerfile
# ✅ BUENO: Multi-stage build con imagen mínima
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

## 📝 Notas

- Las reglas se cargan automáticamente desde este directorio
- Puedes deshabilitar reglas específicas editando o eliminando archivos
- Los regexes usan sintaxis Rust (crate `regex`)
- Scope soportados: `instruction`, `stage`, `file`
