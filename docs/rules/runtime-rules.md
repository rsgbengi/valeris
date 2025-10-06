# Docker Runtime Security Rules

Este directorio contiene reglas YAML para análisis de contenedores Docker en ejecución (runtime).

## 📋 Categorías de Reglas

### 🔐 Seguridad de Contenedores (Security)

#### Modos Privilegiados y Capabilities
- `privileged_mode` (HIGH) - Detecta modo privilegiado habilitado
- `capabilities` (HIGH) - Capabilities peligrosas: SYS_ADMIN, NET_ADMIN, SYS_MODULE, SYS_PTRACE
- `no_new_privileges` (MEDIUM) - No-new-privileges no configurado (permite escalada)

#### Perfiles de Seguridad
- `seccomp_unconfined` (HIGH) - Seccomp deshabilitado (sin filtrado de syscalls)
- `apparmor` (MEDIUM) - AppArmor deshabilitado o unconfined
- `security_options` (MEDIUM) - Opciones de seguridad no configuradas

#### Linux Security Modules
- `user_namespace` (MEDIUM) - User namespaces no habilitados (remapping UID/GID)

### 🗂️ Sistema de Archivos y Montajes (Mounts)

#### Montajes Sensibles
- `mounts` (HIGH) - Montaje de paths sensibles: /var/run/docker.sock, /proc, /sys, /etc, /root
- `writable_sensitive_mounts` (CRITICAL) - Montajes writable de /etc, /boot, /lib, /usr
- `mount_propagation` (HIGH) - Propagación peligrosa: shared, rshared, slave, rslave

#### Sistema de Archivos
- `readonly_rootfs` (MEDIUM) - Root filesystem no read-only
- `tmpfs_exec` (MEDIUM) - tmpfs sin flag noexec (permite ejecución desde memoria)

### 🌐 Configuración de Red (Network)

#### Modos de Red
- `network_mode` (MEDIUM) - Network mode host (sin aislamiento)
- `legacy_links` (LOW) - Uso de --link deprecado (usar user-defined networks)

#### Exposición de Puertos
- `exposed_ports` (MEDIUM) - Puertos sensibles expuestos: 22 (SSH), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), etc.
- `port_all_interfaces` (MEDIUM) - Puertos bound a 0.0.0.0 (todas las interfaces)

#### DNS y Resolución
- `custom_dns` (LOW) - DNS servers personalizados (posible exfiltración)
- `extra_hosts` (INFO) - Entradas personalizadas en /etc/hosts

### 🔧 Namespaces y Aislamiento

- `ipc_mode` (MEDIUM) - IPC mode host (sin aislamiento IPC)
- `pid_mode` (MEDIUM) - PID mode host (puede ver todos los procesos)
- `uts_mode` (MEDIUM) - UTS mode host (comparte hostname/domain)

### 📊 Recursos y Límites (Resources)

#### Límites de Recursos
- `resource_cpu_limit` (LOW) - Sin límites de CPU
- `resource_memory_limit` (LOW) - Sin límites de memoria
- `pid_limits` (LOW) - Sin límites de PIDs (fork bombs)

#### CGroups
- `cgroup_parent` (LOW) - CGroup parent personalizado (puede evadir límites)

### 👤 Usuarios y Permisos (Users)

- `root_user` (HIGH) - Usuario root (UID 0)

### 🔑 Secretos y Configuración (Secrets)

- `secrets_in_env` (CRITICAL) - Secretos hardcoded en variables de entorno (PASSWORD, SECRET, TOKEN, API_KEY)

### 🔄 Políticas de Reinicio (Restart)

- `restart_policy` (LOW) - Always restart sin health check (puede ocultar fallos)

### 📝 Logging y Monitoreo (Logging)

- `log_driver` (LOW) - Logging local (json-file) en lugar de centralizado
- `log_no_limit` (MEDIUM) - Sin límites de logs (riesgo de disco lleno)
- `no_healthcheck` (INFO) - Sin HEALTHCHECK configurado

### 🖼️ Imágenes y Versiones (Images)

- `latest_tag` (MEDIUM) - Uso de tag 'latest' (no determinístico)
- `image_no_digest` (INFO) - Imagen sin digest SHA256
- `old_image` (LOW) - Imagen potencialmente desactualizada (>90 días)

### ⚙️ Configuración Avanzada (Advanced)

- `device_access` (HIGH) - Acceso a dispositivos del host (/dev/*)
- `sysctls` (HIGH) - Modificación de parámetros del kernel vía sysctl

## 📊 Distribución por Severidad

- **CRITICAL**: 2 reglas (secretos, montajes writable sensibles)
- **HIGH**: 9 reglas (privileged, capabilities, seccomp, devices, sysctls, mounts)
- **MEDIUM**: 12 reglas (network, security profiles, logs, images)
- **LOW**: 8 reglas (recursos, restart, DNS, links)
- **INFO**: 3 reglas (healthcheck, digest, hosts)

**Total: 34 reglas** (17 existentes + 17 nuevas)

## 🎯 Reglas Nuevas Agregadas

### Montajes (3 reglas)
- `mount_propagation` - Propagación peligrosa de montajes
- `writable_sensitive_mounts` - Escritura en /etc, /boot, /lib
- `tmpfs_exec` - tmpfs sin noexec

### Red (4 reglas)
- `port_all_interfaces` - Puertos en 0.0.0.0
- `dns_settings` - DNS personalizado
- `extra_hosts` - /etc/hosts personalizado
- `network_links` - Links deprecados

### Logging (3 reglas)
- `log_driver` - Sin logging centralizado
- `log_size_limit` - Sin límites de logs
- `healthcheck` - Sin health check

### Imágenes (3 reglas)
- `image_tag` - Tag 'latest'
- `image_no_digest` - Sin digest
- `outdated_image` - Imagen antigua

### Seguridad Runtime (6 reglas)
- `apparmor` - AppArmor disabled
- `seccomp` - Seccomp unconfined
- `no_new_privileges` - Permite escalada
- `cgroup_parent` - CGroup custom
- `device_access` - Acceso a devices
- `sysctls` - Sysctls peligrosos

## 🚀 Uso

```bash
# Escanear todos los contenedores
cargo run -- scan

# Escanear solo contenedores running
cargo run -- scan --state running

# Usar solo reglas específicas
cargo run -- scan --only privileged_mode,capabilities

# Excluir reglas específicas
cargo run -- scan --exclude readonly_rootfs

# Exportar a JSON
cargo run -- scan --format json --output results.json
```

## 📝 Ejemplos de JSONPath

Las reglas usan JSONPath para extraer datos del Docker inspect API:

```yaml
# Detectar capabilities peligrosas
jsonpath: "$.HostConfig.CapAdd[*]"
regex: "SYS_ADMIN|ALL|NET_ADMIN"

# Combinar múltiples campos
parts:
  - jsonpath: "$.Mounts[*].Source"
  - jsonpath: "$.Mounts[*].RW"
separator: ":"
regex: "^/etc:true$"

# Verificar campos ausentes
jsonpath: "$.Config.Healthcheck"
missing: true
```

## 🔍 Container JSON Structure

Las reglas inspeccionan la respuesta de `docker inspect`:

```json
{
  "Id": "abc123...",
  "Config": {
    "Image": "nginx:latest",
    "User": "root",
    "Env": ["PASSWORD=secret"],
    "Healthcheck": {...}
  },
  "HostConfig": {
    "Privileged": false,
    "CapAdd": ["NET_ADMIN"],
    "SecurityOpt": ["seccomp=unconfined"],
    "Mounts": [...],
    "NetworkMode": "host",
    "PidMode": "host"
  },
  "Mounts": [
    {
      "Source": "/var/run/docker.sock",
      "Destination": "/var/run/docker.sock",
      "RW": true
    }
  ]
}
```

## 📚 Referencias

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Docker Inspect API](https://docs.docker.com/engine/api/v1.43/#tag/Container/operation/ContainerInspect)
