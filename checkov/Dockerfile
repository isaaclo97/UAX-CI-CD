# ============================================================
# DOCKERFILE VULNERABLE
# Vulnerabilidades: root user, imagen sin tag, secrets en ENV,
# sin HEALTHCHECK, sin .dockerignore, capabilidades peligrosas
# ============================================================

# VULNERABLE: Imagen sin tag específico (usa "latest" implícito)
# Debería ser: FROM python:3.11-slim
FROM python:latest

# VULNERABLE: Ejecuta todo como root (sin USER definido)
# No hay instrucción USER

# VULNERABLE: Secretos hardcodeados en variables de entorno
ENV DATABASE_PASSWORD="SuperSecret123!"
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV API_KEY="sk-prod-abc123xyz789secretkey"

# VULNERABLE: Instala paquetes sin fijar versiones (supply chain risk)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    ssh \
    sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# VULNERABLE: Copia todo el contexto incluyendo potenciales .env, .git, etc.
# Sin .dockerignore definido
COPY . .

# VULNERABLE: Instala dependencias sin hash verification
RUN pip install -r requirements.txt

# VULNERABLE: Puerto privilegiado (< 1024)
EXPOSE 80

# VULNERABLE: Sin HEALTHCHECK definido
# No hay instrucción HEALTHCHECK

# VULNERABLE: Ejecuta la app directamente sin tini/dumb-init (zombie processes)
CMD ["python", "app.py"]
