# ─────────────────────────────────────────────────────────────────
# Acronis VM Monitor – Dockerfile
# Imagen única usada por ambos servicios (monitor y api).
# El comando de entrada se define en docker-compose.yml.
# ─────────────────────────────────────────────────────────────────

# Python slim para imagen liviana (~150MB final)
FROM python:3.11-slim

# Metadatos
LABEL maintainer="Acronis VM Monitor"
LABEL description="Acronis VM Monitor – Backend & Dashboard"

# Variables de entorno base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# 1. Copiar solo requirements primero (aprovecha cache de Docker)
COPY requirements.txt .

# 2. Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# 3. Copiar el código fuente
COPY acronis_db.py     .
COPY acronis_monitor.py .
COPY api_server.py     .
COPY notification_engine.py .
COPY get_inventory.py  .
COPY list_vms.py       .
COPY index.html        .

# El directorio /app/data se usa como volumen compartido
# entre el servicio monitor y el servicio api.
# La DB SQLite y el monitor_status.json se almacenan ahí.
RUN mkdir -p /app/data

# Exponer puerto de la API (solo aplica al servicio api)
EXPOSE 8085

# Health check para el servicio API
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8085/health')" || exit 1

# Comando por defecto (sobreescrito en docker-compose.yml por servicio)
CMD ["python", "api_server.py"]
