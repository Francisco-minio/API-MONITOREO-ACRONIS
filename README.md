# Acronis VM Monitor & Alert System 🚀

Sistema integral de monitoreo y alertas para infraestructura de Acronis Cyber Protect, diseñado para centralizar el estado de protección de servidores, estaciones de trabajo y servicios cloud (M365/Google Workspace) en un dashboard moderno y reactivo.

## 📋 Descripción General
Este proyecto permite visualizar en tiempo real el estado de **todos** los recursos protegidos por Acronis. Detecta automáticamente fallos de backup, puntuaciones bajas de CyberFit, cambios de estado críticos y alertas nativas de la consola de Acronis. Incluye un motor de notificaciones inteligente vía Telegram con lógica anti-spam y resoluciones automáticas.

---

## ✨ Características Principales

### 🖥️ Dashboard Inteligente
*   **Visibilidad Dinámica**: Interfaz moderna con modo oscuro, tarjetas interactivas y filtros por cliente (Tenant).
*   **Monitoreo Multitipo**: Ahora soporta no solo servidores y workstations, sino también buzones de M365, sitios de SharePoint, OneDrive y otros recursos cloud.
*   **Gestión Masiva**: Botones para mostrar/ocultar equipos y activar/desactivar alertas de forma masiva o por cliente.
*   **Etiquetas y Clasificación**: Soporte para etiquetas personalizadas para organizar recursos por criticidad o función.
*   **Historial de Cambios**: Registro detallado de cada modificación detectada en el inventario.

### 📊 Reportes Ejecutivos e Históricos de Respaldo
*   **Generación Bajo Demanda**: Selector de rango de fechas (*Últimos 7 días*, *14 días*, *Último mes* o fechas personalizadas) con previsualización HTML en tiempo real dentro del Dashboard.
*   **Envío Automático Programable**: Configuración del día de la semana (Lunes por defecto) y hora exacta (Zona Horaria Chile UTC-4) para el envío automático a Francisco, Pablo y otros destinatarios por correo electrónico.
*   **Contenido Completo del Informe**:
    *   **KPIs Ejecutivos**: Total de equipos protegidos, tasa de éxito %, respaldos exitosos, advertencias y fallidos.
    *   **Distribución por Plan**: Conteo de equipos agrupados por cada Plan de Protección aplicado.
    *   **Diagnóstico de Incidencias**: Lista detallada de equipos con fallos o advertencias, incluyendo la causa raíz exacta devuelta por la API de Acronis.
    *   **Detalle de Servidores / BBDD**: Fecha/hora del último punto de recuperación y cálculo de antigüedad (alertando visualmente si supera 24h o 48h).
    *   **Capacidad de Almacenamiento Local (NTFS) & Cloud**: Medidores de capacidad total, usada, disponible y % de uso, con **alerta destacada en rojo ante riesgo de agotamiento** (>85% o umbral configurable).
*   **Persistencia Histórica**: Base de datos SQLite local (`backup_executions` y `storage_history`) para conservar el historial sin restricciones de retención de Acronis.

### 🔔 Motor de Notificaciones (Multicanal: Telegram + Email SMTP)
*   **Alertas Personalizadas**: 
    *   **Respaldos Exitosos**: Notificación de confirmación cada vez que un equipo o recurso cloud completa un respaldo de forma exitosa en Acronis.
    *   Backup atrasado (>25h advertencia, >48h crítico).
    *   Equipos sin registro histórico de backups.
    *   Cambios de estado (Critical/Warning/OK) en la protección de Acronis.
    *   Puntuación de CyberFit por debajo del umbral configurado.
*   **Envío Multicanal**: Despacho simultáneo por Telegram y Email HTML formateado con diseño oscuro acorde al Dashboard.
*   **Fuentes Híbridas**: Combina reglas propias de negocio con alertas nativas de la API de Acronis (amenazas detectadas, ransomware, agentes offline).
*   **Anti-Spam e Inteligencia**:
    *   Lógica de re-notificación programable (por defecto cada 6 horas).
    *   Resolución automática de alertas enviada a Telegram y Email cuando el problema se soluciona.
    *   **Silenciado Temporal**: Capacidad de silenciar alertas de equipos específicos hasta una fecha determinada.

### 🏗️ Arquitectura del Sistema
El sistema se divide en 4 componentes principales:
1.  **`acronis_monitor.py` (Poller)**: Consulta la API de Acronis, normaliza recursos, colecta actividades de backup (Task Manager API) y monitorea el almacenamiento local/cloud.
2.  **`acronis_db.py` (Capa de Datos)**: SQLite WAL con tablas de máquinas, historial, notificaciones, ejecuciones de backup (`backup_executions`) y muestreo de almacenamiento (`storage_history`).
3.  **`notification_engine.py` (Worker & Scheduler)**: Evalúa reglas, despacha alertas multicanal y programa el envío automático semanal del Reporte Ejecutivo.
4.  **`api_server.py` (REST API & Dashboard)**: Sirve el frontend, endpoints de inventario, configuración de canales y generación/envío de reportes bajo demanda.

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
    Crea un archivo `.env` basado en `.env.example` y completa tus credenciales.

3.  **Levantar el Sistema**:
    ```bash
    docker compose up -d
    ```

El dashboard estará disponible en: `http://localhost:8085`

---

## 🔄 Mantenimiento y Actualización

Para actualizar el sistema en un servidor Linux con los últimos cambios del repositorio:

```bash
# 1. Obtener la última versión del código
git pull origin main

# 2. Reconstruir imágenes y reiniciar servicios
sudo docker-compose up -d --build
```

---

## ⚙️ Configuración de Alertas (Telegram y Email SMTP)

1.  Accede a la pestaña **Canales** en el Dashboard (`http://localhost:8085`).
2.  **Telegram**: Ingresa tu **Bot Token** y los **Chat IDs** de destino. Activa el canal y guarda.
3.  **Email (SMTP)**: Configura el servidor SMTP (host, puerto, usuario, contraseña, remitente y destinatarios). Activa el canal y presiona **Probar canal** para verificar la entrega.
4.  En la vista principal, activa el toggle de alertas para las máquinas o servicios que deseas monitorear activamente.

---

## ⏱️ Zona Horaria
El sistema está configurado por defecto para la **Zona Horaria de Chile (Santiago, UTC-4)**. Esto asegura que los logs de auditoría y las notificaciones coincidan con la hora local de operación.

## 📄 Notas Técnicas
*   **Base de Datos**: Se utiliza SQLite para portabilidad, mapeado a un volumen de Docker para persistencia.
*   **Migraciones**: El script `acronis_db.py` actualiza la estructura de la base de datos automáticamente si se detectan cambios en el esquema.

---
**Desarrollado para la gestión eficiente y proactiva de backups.**
