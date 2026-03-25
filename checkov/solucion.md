# Solución: Análisis de seguridad IaC con Checkov
**Ejercicio práctico — Escaneo de infraestructura vulnerable**

---

## ¿Qué es Checkov?

Checkov es una herramienta de análisis estático de seguridad para infraestructura como código (IaC). Detecta malas configuraciones en:

- Terraform
- Dockerfiles
- Kubernetes (YAML)
- GitHub Actions
- CloudFormation, Helm, ARM templates, y más

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

Al ejecutar `checkov -f main.tf` puede aparecer este error:

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
/Users/usuario/Library/Python/3.9/bin/checkov -f main.tf
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
# Escanear un archivo concreto
checkov -f main.tf

# Escanear el directorio completo
checkov -d .

# Exportar resultados en JSON
checkov -f main.tf --output json > resultados.json
```

> **Nota sobre GitHub Actions:** Checkov solo detecta workflows de GitHub Actions si los archivos están dentro de `.github/workflows/`. Ejecutar `checkov -f workflow.yml` desde otro directorio no produce resultados.

---

## Paso 4 — Resultados obtenidos (archivos vulnerables)

| Scanner | Pasados | Fallos | Total |
|---|---|---|---|
| Terraform (`main.tf`) | 11 | 44 | 55 |
| Kubernetes (`kubernetes.yaml`) | 71 | 26 | 97 |
| Dockerfile | 58 | 4 | 62 |
| GitHub Actions (`github-actions.yml` + `deploy.yml`) | 0 | 8 | 8 |
| **TOTAL** | **140** | **82** | **222** |

**82 checks fallidos** sobre 222 comprobaciones totales = **36.9% de fallos**

---

## Paso 5 — Análisis de vulnerabilidades detectadas

### A) Terraform — `main.tf` (44 fallos)

#### S3 Bucket (`aws_s3_bucket.datos_empresa`)

| Check | Descripción |
|---|---|
| `CKV_AWS_20` | ACL pública de LECTURA — cualquiera puede leer los objetos |
| `CKV_AWS_57` | ACL pública de ESCRITURA — cualquiera puede subir/modificar objetos |
| `CKV2_AWS_6` | Sin bloqueo de acceso público (PublicAccessBlock) |
| `CKV_AWS_21` | Sin versionado — no hay recuperación ante borrados |
| `CKV_AWS_18` | Sin logging de accesos al bucket |
| `CKV_AWS_145` | Sin cifrado KMS por defecto |
| `CKV2_AWS_62` | Sin notificaciones de eventos configuradas |

#### Instancia EC2 (`aws_instance.servidor_web`)

| Check | Descripción |
|---|---|
| `CKV_AWS_79` | IMDSv2 no obligatorio (`http_tokens = "optional"`) — permite SSRF al metadata service **[CRÍTICO]** |
| `CKV_AWS_88` | IP pública asignada directamente — instancia expuesta a internet |
| `CKV_AWS_8` | Disco EBS raíz sin cifrar |
| `CKV_AWS_126` | Monitorización detallada desactivada |

#### Security Group (`aws_security_group.sg_web`)

| Check | Descripción |
|---|---|
| `CKV_AWS_24` | SSH (puerto 22) abierto a `0.0.0.0/0` |
| `CKV_AWS_25` | RDP (puerto 3389) abierto a `0.0.0.0/0` |
| `CKV_AWS_382` | Todo el tráfico de salida permitido (egress sin restricción) |
| `CKV_AWS_23` | Sin descripción en las reglas del security group |

#### RDS (`aws_db_instance.base_datos`)

| Check | Descripción |
|---|---|
| `CKV_AWS_17` | Base de datos accesible públicamente |
| `CKV_AWS_16` | Almacenamiento sin cifrar en reposo |
| `CKV_AWS_133` | Sin backups automáticos (`retention = 0`) |
| `CKV_AWS_157` | Sin Multi-AZ (sin alta disponibilidad) |
| `CKV_AWS_129` | Sin logs de auditoría habilitados |
| `CKV_AWS_161` | Sin autenticación IAM habilitada |
| `CKV_AWS_118` | Sin monitorización mejorada |

#### IAM Policy (`aws_iam_policy.politica_admin`)

| Check | Descripción |
|---|---|
| `CKV_AWS_62` | Política con `*:*` — permite cualquier acción sobre cualquier recurso |
| `CKV_AWS_63` | `Action = "*"` en la política |
| `CKV_AWS_355` | `Resource = "*"` para acciones restrictables |
| `CKV_AWS_286` | Permite escalada de privilegios |
| `CKV_AWS_287` | Permite exposición de credenciales |
| `CKV_AWS_288` | Permite exfiltración de datos |
| `CKV_AWS_289` | Permite gestión de permisos sin restricciones |
| `CKV_AWS_290` | Permite escritura sin restricciones |
| `CKV2_AWS_40` | Privilegios IAM completos |

#### CloudTrail (`aws_cloudtrail.trail`)

| Check | Descripción |
|---|---|
| `CKV_AWS_36` | Validación de integridad de logs desactivada — un atacante puede modificar logs sin detección |
| `CKV_AWS_35` | Logs no cifrados con KMS |
| `CKV_AWS_67` | No habilitado en todas las regiones |
| `CKV2_AWS_10` | Sin integración con CloudWatch Logs |

---

### B) Dockerfile (4 fallos)

| Check | Descripción |
|---|---|
| `CKV_DOCKER_7` | Imagen base `python:latest` sin tag específico — supply chain risk |
| `CKV_DOCKER_3` | No se define `USER` — la app corre como root |
| `CKV_DOCKER_2` | Sin `HEALTHCHECK` — Docker no detecta si la app cae |
| `CKV_DOCKER_4` | Secretos hardcodeados en variables `ENV` |

---

### C) Kubernetes — `kubernetes.yaml` (26 fallos, selección de críticos)

| Check | Descripción |
|---|---|
| `CKV_K8S_16` | `runAsUser: 0` — contenedor ejecutándose como root |
| `CKV_K8S_6` | `privileged: true` — acceso completo al kernel del host |
| `CKV_K8S_25` | `allowPrivilegeEscalation: true` |
| `CKV_K8S_28` | Capability `SYS_ADMIN` habilitada — permite escape de contenedor **[CRÍTICO]** |
| `CKV_K8S_30` | Capability `NET_ADMIN` habilitada |
| `CKV_K8S_32` | `hostPID: true` — acceso a procesos del host |
| `CKV_K8S_4` | `hostNetwork: true` — usa la red del nodo directamente |
| `CKV_K8S_11` | Sin límites de CPU |
| `CKV_K8S_12` | Sin límites de memoria |
| `CKV_K8S_14` | Sin `readinessProbe` |
| `CKV_K8S_8` | Sin `livenessProbe` |
| `CKV_K8S_22` | `readOnlyRootFilesystem: false` — filesystem raíz escribible |
| `CKV_K8S_37` | Secretos en variables de entorno en texto plano |

---

### D) GitHub Actions — `github-actions.yml` y `deploy.yml` (8 fallos)

| Check | Archivo | Descripción |
|---|---|---|
| `CKV_GHA_7` | `github-actions.yml` | `pull_request_target` con checkout del fork — permite a código no confiable acceder a secretos del repo base **[CRÍTICO]** |
| `CKV_GHA_1` | `github-actions.yml` | Actions sin pinning a SHA — los tags pueden ser movidos con force-push |
| `CKV2_GHA_1` | `github-actions.yml` | Permisos excesivos a nivel de workflow (write en todo) |
| `CKV_GHA_3` | `github-actions.yml` | Inyección de comandos via `${{ github.event.pull_request.title }}` sin sanitizar |
| `CKV_GHA_7` | `deploy.yml` | `pull_request_target` con checkout del fork |
| `CKV_GHA_1` | `deploy.yml` | `actions/checkout@v4` sin SHA fijo |
| `CKV2_GHA_1` | `deploy.yml` | Sin permisos top-level (hereda write-all por defecto) |
| — | `deploy.yml` | Auto-aprobación de PRs con `GITHUB_TOKEN` — si el repo tiene branch protection con un solo revisor requerido, esta acción lo salta porque el propio `GITHUB_TOKEN` cuenta como aprobación válida |

---

## Paso 6 — Cómo leer un resultado de Checkov

```
Check: CKV_AWS_24: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
  FAILED for resource: aws_security_group.sg_web
  File: /main.tf:65-92
  Guide: https://docs.prismacloud.io/...
```

| Campo | Significado |
|---|---|
| Check ID | Identificador único de la regla (`CKV_AWS_24`) |
| Descripción | Qué está comprobando |
| `FAILED`/`PASSED` | Resultado |
| `resource` | Recurso de Terraform/K8s afectado |
| `File` | Archivo y líneas donde está el problema |
| `Guide` | Enlace a documentación con la remediación |

---

## Paso 7 — Conexión con ataques reales (Trivy / TeamPCP)

Los checks que fallaron reproducen **exactamente** los vectores usados por TeamPCP en los ataques de marzo 2026:

| Check | Vector real |
|---|---|
| `CKV_GHA_7` | `pull_request_target` mal configurado. El bot `hackerbot-claw` usó este vector para robar el PAT inicial de Trivy |
| `CKV_GHA_1` | Actions sin pinning a SHA. TeamPCP hizo force-push de tags para que workflows que referenciaban `@v0.34.0` ejecutaran código malicioso |
| `CKV_AWS_79` | IMDSv2 no obligatorio. Runners CI sin IMDSv2 permiten SSRF hacia el metadata service, obteniendo credenciales cloud |
| `CKV_K8S_6` | Contenedor privilegiado. TeamPCP creó pods privilegiados en `kube-system` para instalar backdoors persistentes en los nodos |

---

## Archivos corregidos

| Original | Corregido | Fallos → Corregidos |
|---|---|---|
| `Dockerfile` | `Dockerfile.fixed` | 4 → 0 |
| `kubernetes.yaml` | `kubernetes_fixed.yaml` | 26 → 0 |
| `github-actions.yml` | `github-actions_fixed.yml` | 4 → 0 |
| `deploy.yml` | `deploy_fixed.yml` | 4 → 0 |

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

Con un solo comando (`checkov -d .`) se detectaron **82 problemas de seguridad** en infraestructura que, en producción, podrían permitir:

- Acceso no autorizado a datos en S3 (bucket público)
- Robo de credenciales cloud desde el metadata service (IMDS)
- Escalada de privilegios en Kubernetes
- Compromiso de pipelines CI/CD via `pull_request_target`
- Ejecución de código malicioso via supply chain (tags sin pinning)
- Persistencia en el sistema (contenedores privilegiados)
- Bypass de revisión de código via auto-aprobación de PRs

Checkov es gratuito, no requiere infraestructura desplegada (análisis estático) y se puede integrar en cualquier pipeline CI/CD para prevenir estos problemas antes de llegar a producción.

---

## Referencia de comandos

```bash
# Escanear un archivo concreto
checkov -f main.tf

# Escanear directorio completo
checkov -d .

# Solo mostrar fallos (salida más limpia)
checkov -d . --compact

# Exportar a JSON
checkov -d . --output json > resultados.json

# Filtrar checks concretos
checkov -d . --check CKV_AWS_24,CKV_AWS_25

# Excluir un check
checkov -d . --skip-check CKV_AWS_144

# Escanear solo Terraform
checkov -d . --framework terraform

# Escanear GitHub Actions (requiere estructura .github/workflows/)
checkov -d . --framework github_actions
```
