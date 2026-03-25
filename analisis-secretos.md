# Análisis de Secretos Expuestos — UAX CI/CD 2026

Repositorio analizado: https://github.com/isaaclo97/UAX-CI-CD/

---

## Herramienta 1: HackTricks GitHub Leaks

**URL:** https://tools.hacktricks.wiki/github-leaks/index.html

Herramienta online que escanea repositorios públicos de GitHub usando **gitleaks** como motor de detección. No requiere instalación — basta con introducir la URL del repositorio.

**Resultado:** encontró **3 secretos potenciales** en el commit `eb5ea21`:

```
Secret Name:      Q1VQT04tU0VDUkVUTy1VQVgtMjAyNg==
Type:             Detected a Generic API Key
Location:         https://github.com/isaaclo97/UAX-CI-CD/commit/eb5ea21d7e213ebbff74b91e7b74956b9026b87c
Detected by:      gitleaks
Matched Content:  _secret = "Q1VQT04tU0VDUkVUTy1VQVgtMjAyNg=="

Secret Name:      CUPON-SECRETO-UAX-2026
Type:             Detected a Generic API Key
Location:         https://github.com/isaaclo97/UAX-CI-CD/commit/eb5ea21d7e213ebbff74b91e7b74956b9026b87c
Detected by:      gitleaks
Matched Content:  _secret = "CUPON-SECRETO-UAX-2026"
```

> La herramienta decodifica el base64 automáticamente, exponiendo el valor real del secreto.

---

## Herramienta 2: Gitleaks (local)

**Instalación:**

```bash
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
tar -xzf gitleaks_linux_x64.tar.gz
```

**Ejecución sobre el repositorio:**

```bash
# Escanear directorio local (sin git)
gitleaks detect --source . --no-git

# Escanear historial git completo
gitleaks detect --source .

# Exportar resultados en JSON
gitleaks detect --source . --report-format json --report-path resultado.json
```

**Salida obtenida:**

```
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

6:28PM INF  scanned ~24262 bytes (24.26 KB) in 37.6ms
6:28PM WRN  leaks found: 4
```

**Detalle de hallazgos (JSON):**

```json
[
  {
    "RuleID": "generic-api-key",
    "Description": "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
    "StartLine": 41,
    "Match": "_secret = \"Q1VQT04tU0VDUkVUTy1VQVgtMjAyNg==\"",
    "Secret": "Q1VQT04tU0VDUkVUTy1VQVgtMjAyNg==",
    "File": "index.html",
    "Entropy": 3.9025183
  },
  {
    "RuleID": "generic-api-key",
    "Description": "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
    "StartLine": 41,
    "Match": "_secret = \"CUPON-SECRETO-UAX-2026\"",
    "Secret": "CUPON-SECRETO-UAX-2026",
    "File": "index.html",
    "Entropy": 3.788755,
    "Tags": [
      "decoded:base64",
      "decode-depth:1"
    ]
  }
]
```

> Gitleaks detecta el base64 como `generic-api-key` por su entropía, y lo **decodifica automáticamente** en un segundo hallazgo con el tag `decoded:base64`.

---

## Herramienta 3: TruffleHog

**Instalación:**

```bash
brew install trufflehog
```

**Ejecución:**

```bash
trufflehog github --repo https://github.com/isaaclo97/UAX-CI-CD
trufflehog git https://github.com/isaaclo97/UAX-CI-CD --no-verification
```

**Salida obtenida:**

```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

INFO  finished scanning  {"verified_secrets": 0, "unverified_secrets": 0}
```

**Resultado: no encontró nada.**

TruffleHog trabaja con detectores específicos por tipo de secreto (tokens de GitHub, claves de AWS, etc.) y verifica que el secreto sea válido contra la API del servicio. Una cadena base64 arbitraria no coincide con ningún patrón conocido, por lo que **no la detecta**.

---

## Comparativa de herramientas

| Herramienta | Detección base64 custom | Decodifica base64 | Verifica secretos | Requiere instalación |
|-------------|------------------------|-------------------|-------------------|----------------------|
| HackTricks (gitleaks) | ✅ Sí | ✅ Sí | ❌ No | ❌ No (online) |
| Gitleaks | ✅ Sí | ✅ Sí | ❌ No | ✅ Sí |
| TruffleHog | ❌ No | ❌ No | ✅ Sí | ✅ Sí |

> **Conclusión:** para detectar secretos custom o de baja entropía, gitleaks es más efectivo. TruffleHog es mejor para verificar que tokens conocidos (GitHub, AWS, Stripe...) son realmente válidos y activos.

---

*Ejercicio UAX 2026 — Seguridad en CI/CD*
