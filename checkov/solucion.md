# Solución: Análisis de seguridad IaC con Checkov
**Ejercicio práctico — Escaneo de infraestructura vulnerable**

---

## ¿Qué es Checkov?

Checkov es una herramienta de análisis estático de seguridad para infraestructura como código (IaC). Detecta malas configuraciones en:

- Dockerfiles
- Kubernetes (YAML)
- GitHub Actions
- Terraform, CloudFormation, Helm, ARM templates, y más

Es open-source, mantenido por Prisma Cloud (Palo Alto Networks). Cada comprobación tiene un ID único (ej: `CKV_AWS_24`) que corresponde a una política de seguridad concreta y enlaza con documentación oficial.

---

## Paso 1 — Instalación

**Requisito previo:** Python 3.7+

```bash
pip3 install checkov
```

Verificar instalación:

```bash
checkov --version
# checkov 3.2.510
```

---

## Paso 2 — Problema: `checkov: command not found`

Al ejecutar `checkov -d .` puede aparecer este error:

```
zsh: command not found: checkov
```

### ¿Por qué ocurre?

`pip3 install` instala el binario en el directorio de scripts del usuario:
- **Linux:** `~/.local/bin`
- **macOS:** `~/Library/Python/X.Y/bin`

Si ese directorio no está en la variable `PATH` del shell, el sistema no lo encuentra aunque esté instalado.

### Cómo localizarlo

```bash
find ~/Library/Python -name "checkov" 2>/dev/null
# Ejemplo: /Users/usuario/Library/Python/3.9/bin/checkov
```

### Solución inmediata (sin tocar configuración)

```bash
# Ruta completa al binario
/Users/usuario/Library/Python/3.9/bin/checkov -d .
```

### Solución permanente (añadir al PATH)

```bash
# Añadir al ~/.zshrc (o ~/.bashrc si usas bash)
export PATH="$HOME/Library/Python/3.9/bin:$PATH"

# Aplicar sin cerrar la terminal
source ~/.zshrc

# Verificar
which checkov
checkov --version
```

---

## Paso 3 — Lanzar el escaneo

```bash
# Escanear el directorio completo
checkov -d .

# Escanear excluyendo una subcarpeta
checkov -d . --skip-path corregidos

# Exportar resultados en JSON
checkov -d . --output json > resultados.json
```

> **Nota sobre GitHub Actions:** Checkov solo detecta workflows de GitHub Actions si los archivos están dentro de `.github/workflows/`. Ejecutar `checkov -f workflow.yml` desde otro directorio no produce resultados. Para escanear los archivos de esta carpeta hay que copiarlos temporalmente a esa ruta o usar `--framework github_actions -d .` desde la raíz del repo.

---

## Paso 4 — Resultados obtenidos (archivos vulnerables)

```bash
# kubernetes.yaml
checkov --framework kubernetes -f kubernetes.yaml --compact --quiet
checkov --framework secrets   -f kubernetes.yaml --compact --quiet

# Dockerfile
checkov --framework dockerfile -f Dockerfile --compact --quiet
checkov --framework secrets    -f Dockerfile --compact --quiet

# GitHub Actions (requiere que el archivo esté en .github/workflows/)
checkov --framework github_actions -f github-actions.yml --compact --quiet
checkov --framework github_actions -f deploy.yml --compact --quiet
```

| Archivo | Scanner | Pasados | Fallos | Total |
|---|---|---|---|---|
| `kubernetes.yaml` | kubernetes | 71 | 26 | 97 |
| `kubernetes.yaml` | secrets | 0 | 1 | 1 |
| `Dockerfile` | dockerfile | 58 | 4 | 62 |
| `Dockerfile` | secrets | 0 | 3 | 3 |
| `github-actions.yml` | github_actions | 35 | 1 | 36 |
| `deploy.yml` | github_actions | 15 | 1 | 16 |
| **TOTAL** | | **179** | **36** | **215** |

**36 checks fallidos** sobre 215 comprobaciones totales = **16.7% de fallos**

---

## Paso 5 — Análisis de vulnerabilidades detectadas

### A) `Dockerfile` — dockerfile scanner (4 fallos)

| Check | Descripción |
|---|---|
| `CKV_DOCKER_7` | Imagen base `python:latest` sin tag específico — supply chain risk |
| `CKV_DOCKER_3` | No se define `USER` — la app corre como root |
| `CKV_DOCKER_2` | Sin `HEALTHCHECK` — Docker no detecta si la app cae |
| `CKV2_DOCKER_1` | Uso de `sudo` en instrucciones `RUN` |

### `Dockerfile` — secrets scanner (3 fallos)

| Check | Descripción |
|---|---|
| `CKV_SECRET_2` | AWS Access Key hardcodeada (línea 16) |
| `CKV_SECRET_2` | AWS Access Key hardcodeada (línea 17) |
| `CKV_SECRET_6` | Cadena Base64 de alta entropía (línea 18) |

---

### B) `kubernetes.yaml` — kubernetes scanner (26 fallos)

| Check | Descripción |
|---|---|
| `CKV_K8S_16` | `runAsUser: 0` — contenedor ejecutándose como root |
| `CKV_K8S_20` | `allowPrivilegeEscalation: true` |
| `CKV_K8S_39` | Capability `SYS_ADMIN` habilitada — permite escape de contenedor **[CRÍTICO]** |
| `CKV_K8S_28` | Capability `NET_RAW` habilitada |
| `CKV_K8S_25` | Capabilities adicionales asignadas al contenedor |
| `CKV_K8S_37` | `capabilities` no restringidas (`drop: ALL` ausente) |
| `CKV_K8S_17` | `hostPID: true` — acceso a procesos del host |
| `CKV_K8S_19` | `hostNetwork: true` — usa la red del nodo directamente |
| `CKV_K8S_27` | Socket Docker montado en el contenedor — permite escape **[CRÍTICO]** |
| `CKV_K8S_10` | Sin requests de CPU definidos |
| `CKV_K8S_11` | Sin límites de CPU |
| `CKV_K8S_12` | Sin requests de memoria definidos |
| `CKV_K8S_13` | Sin límites de memoria |
| `CKV_K8S_8` | Sin `livenessProbe` |
| `CKV_K8S_9` | Sin `readinessProbe` |
| `CKV_K8S_22` | `readOnlyRootFilesystem: false` — filesystem raíz escribible |
| `CKV_K8S_14` | Imagen con tag `latest` (no fijo) |
| `CKV_K8S_43` | Imagen sin digest SHA — no garantiza inmutabilidad |
| `CKV_K8S_23` | Contenedor corriendo como root (`runAsNonRoot` ausente) |
| `CKV_K8S_40` | UID demasiado bajo — puede colisionar con usuarios del host |
| `CKV_K8S_29` | Sin `securityContext` en pod/contenedor |
| `CKV_K8S_31` | Sin perfil `seccomp` configurado |
| `CKV_K8S_38` | `automountServiceAccountToken` no desactivado |
| `CKV_K8S_21` | Recursos en namespace `default` (no dedicado) |
| `CKV2_K8S_6` | Sin `NetworkPolicy` — pod acepta tráfico de cualquier origen |

### `kubernetes.yaml` — secrets scanner (1 fallo)

| Check | Descripción |
|---|---|
| `CKV_SECRET_2` | AWS Access Key hardcodeada en variables de entorno |

---

### C) `github-actions.yml` — github_actions scanner (1 fallo)

| Check | Descripción |
|---|---|
| `CKV_GHA_2` | Comando shell vulnerable a inyección — valor de evento de GitHub interpolado directamente en `run:` |

### D) `deploy.yml` — github_actions scanner (1 fallo)

| Check | Descripción |
|---|---|
| `CKV2_GHA_1` | Permisos `write-all` a nivel de workflow — concede escritura sobre todo el repositorio |

> **Nota:** Checkov solo detecta workflows de GitHub Actions cuando el archivo está en `.github/workflows/`. Para escanear los archivos de esta carpeta hay que copiarlos temporalmente a esa ruta. Otras malas configuraciones presentes (como `pull_request_target` o actions sin SHA fijo) pueden no tener checks en la versión instalada de Checkov (3.2.510), pero siguen siendo vulnerabilidades reales descritas en el README.

---

## Paso 6 — Cómo leer un resultado de Checkov

```
Check: CKV_K8S_16: "Container should not be privileged"
  FAILED for resource: Deployment.default.app-vulnerable
  File: /kubernetes.yaml:7-80
  Guide: https://docs.prismacloud.io/...
```

| Campo | Significado |
|---|---|
| Check ID | Identificador único de la regla (`CKV_K8S_16`) |
| Descripción | Qué está comprobando |
| `FAILED`/`PASSED` | Resultado |
| `resource` | Recurso Kubernetes/Docker afectado |
| `File` | Archivo y líneas donde está el problema |
| `Guide` | Enlace a documentación con la remediación |

---

## Paso 7 — Conexión con ataques reales (Trivy / TeamPCP)

Los checks que fallaron reproducen vectores usados por TeamPCP en los ataques a Trivy de marzo 2026:

| Check detectado | Vector real relacionado |
|---|---|
| `CKV_GHA_2` (shell injection) | TeamPCP inyectó comandos via valores de eventos de PRs para exfiltrar secretos de entorno en runners CI |
| `CKV2_GHA_1` (write-all permissions) | Permisos excesivos permitieron al `GITHUB_TOKEN` comprometido escribir en ramas protegidas y aprobar PRs maliciosos |
| `CKV_K8S_39` (CAP_SYS_ADMIN) | TeamPCP creó pods con capabilities elevadas en `kube-system` para montar el filesystem del host y escalar privilegios |
| `CKV_K8S_27` (docker socket) | Acceso al socket Docker permite lanzar contenedores privilegiados desde dentro del clúster, escapando el aislamiento |
| `CKV_SECRET_2` (secretos hardcodeados) | Credenciales AWS embebidas directamente en manifiestos — cualquier acceso de lectura al repo o al clúster las expone |

---

## Archivos corregidos

```bash
# Resultado del escaneo sobre carpeta corregidos/
checkov -d corregidos --compact --quiet
# kubernetes scan results: Passed: 102, Failed: 0
# dockerfile scan results: Passed: 60,  Failed: 0

checkov --framework github_actions -d corregidos --compact --quiet
# github_actions scan results: Passed: 56, Failed: 0
```

| Original | Corregido | Fallos totales → Corregidos |
|---|---|---|
| `Dockerfile` | `Dockerfile.fixed` | 7 (4 dockerfile + 3 secrets) → 0 |
| `kubernetes.yaml` | `kubernetes_fixed.yaml` | 27 (26 kubernetes + 1 secret) → 0 |
| `github-actions.yml` | `github-actions_fixed.yml` | 1 → 0 |
| `deploy.yml` | `deploy_fixed.yml` | 1 → 0 |

### `Dockerfile.fixed`
- Imagen `python:3.11-slim` con tag fijo (no `latest`)
- Sin secretos en `ENV` — se inyectan en runtime vía orquestador o Secrets Manager
- Solo paquetes estrictamente necesarios, sin `curl`/`wget`/`ssh`/`sudo`
- Usuario sin privilegios (`appuser`, no `root`)
- Puerto `8080` (no privilegiado)
- `HEALTHCHECK` definido

### `kubernetes_fixed.yaml`
- Namespace dedicado `produccion` (no `default`)
- Sin `hostNetwork` ni `hostPID`
- Imagen con digest SHA fijo (no `latest`)
- `securityContext`: `privileged=false`, `runAsNonRoot=true`, `runAsUser=10000`, `readOnlyRootFilesystem=true`, `allowPrivilegeEscalation=false`, `capabilities: drop: ALL`
- Límites de CPU y memoria definidos
- Secretos montados como **archivos** en `/etc/secrets` (no variables de entorno)
- `livenessProbe` y `readinessProbe` definidos
- Sin montaje del socket de Docker
- `automountServiceAccountToken: false`
- `ServiceAccount` con `Role` mínimo (no `cluster-admin`)
- `NetworkPolicy` que restringe el tráfico entrante y saliente

### `github-actions_fixed.yml`
- `pull_request_target` eliminado
- Permisos mínimos a nivel de workflow y job (`contents: read`)
- Todas las actions con SHA completo fijo (no tags flotantes)
- Sin impresión de secretos en logs
- Sin descarga y ejecución de scripts externos
- Credenciales de registry desde secrets, nunca hardcodeadas
- Inputs no interpolados directamente en comandos shell (pasados como variables de entorno)

### `deploy_fixed.yml`
- `pull_request_target` reemplazado por `pull_request` (sin acceso a secretos del repo base)
- `actions/checkout` con SHA fijo
- Permisos top-level explícitos (`contents: read`, `pull-requests: write`)
- Auto-aprobación eliminada — sustituida por un comentario informativo

> **Advertencia sobre `pull-requests: write`:** Este permiso permite comentar en PRs, pero si el repositorio tiene branch protection con un solo revisor requerido, una action con este permiso podría auto-aprobar PRs y saltarse la revisión humana. Asegúrate de exigir **≥ 2 revisores** si usas este permiso.

---

## Conclusión

Con un solo comando (`checkov -d .`) se detectaron **36 problemas de seguridad** en infraestructura que, en producción, podrían permitir:

- Escalada de privilegios en Kubernetes (contenedores con capabilities elevadas y socket Docker montado)
- Exfiltración de credenciales cloud hardcodeadas (AWS keys en Dockerfile y manifiestos K8s)
- Inyección de comandos en pipelines CI/CD via inputs de eventos GitHub
- Movimiento lateral en el clúster por ausencia de NetworkPolicy
- Persistencia en nodos via montaje del socket Docker y filesystem del host

Checkov es gratuito, no requiere infraestructura desplegada (análisis estático) y se puede integrar en cualquier pipeline CI/CD para prevenir estos problemas antes de llegar a producción.

---

## Referencia de comandos

```bash
# Escanear directorio completo
checkov -d .

# Excluir subcarpeta (ej. los corregidos)
checkov -d . --skip-path corregidos

# Solo mostrar fallos (salida más limpia)
checkov -d . --compact --quiet

# Exportar a JSON
checkov -d . --output json > resultados.json

# Filtrar checks concretos
checkov -d . --check CKV_K8S_16,CKV_K8S_39

# Excluir un check
checkov -d . --skip-check CKV_K8S_43

# Escanear solo Kubernetes
checkov -d . --framework kubernetes

# Escanear solo Dockerfiles
checkov -d . --framework dockerfile

# Escanear GitHub Actions (requiere estructura .github/workflows/)
checkov -d . --framework github_actions
```
