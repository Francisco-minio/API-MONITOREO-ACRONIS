# Acronis VM Monitor & Alert System 🚀

Sistema integral de monitoreo y alertas para infraestructura de Acronis Cyber Protect, diseñado para centralizar el estado de protección de servidores y estaciones de trabajo en un dashboard moderno y reactivo.

## 📋 Descripción General
Este proyecto permite visualizar en tiempo real el estado de todos los recursos protegidos por Acronis, detectando automáticamente fallos de backup, puntuaciones bajas de CyberFit y cambios de estado críticos. Incluye un sistema de notificaciones inteligente vía Telegram para una respuesta rápida ante incidencias.

---

## ✨ Características Principales

### 🖥️ Dashboard Inteligente
*   **Visibilidad Dinámica**: Interfaz moderna con modo oscuro, tarjetas interactivas y filtros por cliente (Tenant).
*   **Monitoreo de Salud**: Indicadores de éxito de backup, versiones de agentes y puntuaciones de seguridad.
*   **Gestión Masiva**: Botones para mostrar/ocultar equipos y activar/desactivar alertas de forma masiva o por cliente.
*   **Historial de Cambios**: Registro detallado de cada modificación detectada en el inventario.

### 🔔 Motor de Notificaciones (Telegram)
*   **Alertas Personalizadas**: 
    *   Backup atrasado (>25h advertencia, >48h crítico).
    *   Servidores sin registro histórico de backups.
    *   Cambios de estado (Critical/Warning/OK) en la protección de Acronis.
    *   Puntuación de CyberFit por debajo del umbral configurado.
*   **Anti-Spam**: Lógica de re-notificación cada 6 horas y resolución automática de alertas.
*   **Selección Individual**: Elige qué servidores específicos deben enviar alertas y cuáles no desde la barra lateral.

### 🏗️ Arquitectura del Sistema
El sistema se divide en 4 componentes principales:
1.  **`acronis_monitor.py` (Poller)**: Consulta la API de Acronis cada X segundos, normaliza los datos y detecta cambios.
2.  **`acronis_db.py` (Capa de Datos)**: Gestiona una base de datos SQLite con migraciones automáticas.
3.  **`notification_engine.py` (Worker)**: Evalúa las reglas de negocio y gestiona los envíos a Telegram.
4.  **`api_server.py` (REST API)**: Sirve los datos al frontend y gestiona las preferencias de configuración.

---

## 🛠️ Requisitos e Instalación

### Necesidades Especiales
*   **Credenciales Acronis**: Requiere un `Client ID` y `Client Secret` generados desde la consola de Acronis (Ajustes -> Claves de API).
*   **Docker & Docker Compose**: Recomendado para una implementación rápida y aislada.
*   **Python 3.9+**: Soporta sistemas locales con versiones modernas de Python.

### Instalación con Docker (Recomendado)

1.  **Clonar el repositorio**:
    ```bash
    git clone https://github.com/Francisco-minio/API-MONITOREO-ACRONIS.git
    cd API-MONITOREO-ACRONIS
    ```

2.  **Configurar Variables de Entorno**:
    Crea un archivo `.env` basado en `.env.example`:
    ```ini
    ACRONIS_CLIENT_ID=tu_client_id
    ACRONIS_CLIENT_SECRET=tu_client_secret
    ACRONIS_DC_URL=https://us5-cloud.acronis.com
    POLLING_INTERVAL_SECONDS=300
    CYBERFIT_THRESHOLD=500
    ```

3.  **Levantar el Sistema**:
    ```bash
    docker compose up -d
    ```

El dashboard estará disponible en: `http://localhost:8085`

---

## ⚙️ Configuración de Alertas (Telegram)

Para recibir alertas en tu celular:
1.  Accede a la pestaña **Configuración** en el Dashboard.
2.  Ingresa tu **Bot Token** de Telegram (obtenido de @BotFather).
3.  Ingresa los **Chat IDs** de destino (separados por coma si son varios).
4.  Activa el canal y haz clic en **Guardar**.
5.  En la barra lateral (**Equipos Visibles**), haz clic en el icono de Telegram de los servidores que deseas monitorear.

---

## ⏱️ Zona Horaria
El sistema está configurado por defecto para la **Zona Horaria de Chile (Santiago, UTC-4)**. Esto asegura que los logs de auditoría y las notificaciones de Telegram coincidan con la hora local de operación.

## 📄 Notas Técnicas
*   **Base de Datos**: Se utiliza SQLite para mayor portabilidad. El archivo se mapea a un volumen de Docker para persistencia.
*   **Migraciones**: El script `acronis_db.py` incluye lógica para actualizar la estructura de la base de datos automáticamente si se añaden nuevos campos.

---
**Desarrollado con ❤️ para la gestión eficiente de backups.**
