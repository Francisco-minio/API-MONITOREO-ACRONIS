"""
acronis_db.py
Capa de base de datos SQLite para el Monitor de Acronis.
Gestiona: estado actual de máquinas, historial de cambios y configuración del dashboard.
"""
import sqlite3
import json
import os
from typing import Optional, List
from datetime import datetime, timezone

# DATA_DIR permite montar un volumen Docker: -e DATA_DIR=/app/data
_DATA_DIR = os.getenv('DATA_DIR', os.path.dirname(os.path.abspath(__file__)))
os.makedirs(_DATA_DIR, exist_ok=True)
DB_PATH = os.getenv('DB_PATH', os.path.join(_DATA_DIR, 'acronis_monitor.db'))

# ─────────────────────────── Conexión ──────────────────────────────────────

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # escrituras concurrentes
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

# ─────────────────────────── Inicialización ────────────────────────────────

def init_db():
    """Crea las tablas si no existen."""
    with get_conn() as conn:
        conn.executescript("""
            -- Estado actual de cada máquina (una fila por VM)
            CREATE TABLE IF NOT EXISTS machines (
                vm_id               TEXT PRIMARY KEY,
                name                TEXT,
                tenant_id           TEXT,
                tenant_name         TEXT,
                agent_version       TEXT,
                protection_plan     TEXT,
                protection_status   TEXT,
                cyberfit_score      INTEGER DEFAULT 0,
                last_backup_success TEXT,
                next_backup         TEXT,
                backup_size_gb      REAL DEFAULT 0,
                last_antimalware    TEXT,
                next_antimalware    TEXT,
                alerts              TEXT DEFAULT '[]',  -- JSON array
                visible             INTEGER DEFAULT 1,  -- 1 = visible en dashboard
                pinned              INTEGER DEFAULT 0,  -- 1 = fijada arriba
                notify_telegram     INTEGER DEFAULT 0,  -- 1 = enviar alertas Telegram
                dashboard_order     INTEGER DEFAULT 9999,
                first_seen          TEXT,
                last_seen           TEXT,
                last_changed        TEXT,               -- última vez que algo cambió
                muted_until         TEXT,               -- ISO timestamp hasta cuándo silenciar
                tags                TEXT DEFAULT '[]'   -- JSON array de etiquetas
            );

            -- Historial: un registro cada vez que cambia algo relevante
            CREATE TABLE IF NOT EXISTS history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                vm_id           TEXT NOT NULL,
                vm_name         TEXT,
                tenant_name     TEXT,
                timestamp       TEXT NOT NULL,
                field_changed   TEXT NOT NULL,          -- campo que cambió
                old_value       TEXT,
                new_value       TEXT,
                severity        TEXT DEFAULT 'info'     -- info | warning | critical
            );

            -- Configuración global del dashboard
            CREATE TABLE IF NOT EXISTS dashboard_config (
                key     TEXT PRIMARY KEY,
                value   TEXT NOT NULL
            );

            -- Índices
            CREATE INDEX IF NOT EXISTS idx_history_vm   ON history(vm_id);
            CREATE INDEX IF NOT EXISTS idx_history_ts   ON history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_machines_tenant ON machines(tenant_id);

            -- ─── Registro de notificaciones enviadas (anti-spam) ───────────
            -- Una fila por (vm_id + alert_type). Se reutiliza mientras la
            -- condición siga activa; se marca resuelta cuando desaparece.
            CREATE TABLE IF NOT EXISTS notifications_sent (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                vm_id           TEXT NOT NULL,
                vm_name         TEXT,
                tenant_name     TEXT,
                alert_type      TEXT NOT NULL,   -- BACKUP_OVERDUE_25H | BACKUP_OVERDUE_48H |
                                                 -- CYBERFIT_LOW | STATUS_CRITICAL | etc.
                severity        TEXT NOT NULL,   -- warning | critical
                first_sent      TEXT NOT NULL,   -- ISO timestamp primer envío
                last_sent       TEXT NOT NULL,   -- ISO timestamp último envío
                send_count      INTEGER DEFAULT 1,
                acknowledged    INTEGER DEFAULT 0, -- 1 = operador lo atendió
                resolved_at     TEXT,              -- cuando la condición desapareció
                channel         TEXT DEFAULT 'telegram',
                extra_data      TEXT DEFAULT '{}'  -- JSON con detalles adicionales
            );

            -- ─── Historial de ejecuciones de respaldos (Task Manager / Activities) ───
            CREATE TABLE IF NOT EXISTS backup_executions (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                activity_id         TEXT UNIQUE,
                vm_id               TEXT,
                vm_name             TEXT,
                tenant_id           TEXT,
                tenant_name         TEXT,
                plan_name           TEXT,
                start_time          TEXT,
                end_time            TEXT,
                duration_seconds    INTEGER DEFAULT 0,
                result              TEXT NOT NULL, -- success | warning | failed
                error_message       TEXT,
                size_bytes          INTEGER DEFAULT 0,
                storage_target      TEXT DEFAULT 'cloud_acronis', -- local_ntfs | cloud_acronis
                created_at          TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_exec_vm_id   ON backup_executions(vm_id);
            CREATE INDEX IF NOT EXISTS idx_exec_end_time ON backup_executions(end_time);
            CREATE INDEX IF NOT EXISTS idx_exec_tenant   ON backup_executions(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_exec_result   ON backup_executions(result);

            -- ─── Historial de capacidad de almacenamiento (NTFS local y Cloud) ───────
            CREATE TABLE IF NOT EXISTS storage_history (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id           TEXT,
                tenant_name         TEXT,
                storage_name        TEXT,
                storage_type        TEXT NOT NULL, -- local_ntfs | cloud_acronis
                total_bytes         INTEGER DEFAULT 0,
                used_bytes          INTEGER DEFAULT 0,
                free_bytes          INTEGER DEFAULT 0,
                usage_percent       REAL DEFAULT 0.0,
                timestamp           TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_storage_ts   ON storage_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_storage_type ON storage_history(storage_type);

            -- ─── Almacenamiento y cuotas por Tenant / Cliente ─────────────────────────
            CREATE TABLE IF NOT EXISTS tenant_storage (
                tenant_id           TEXT PRIMARY KEY,
                tenant_name         TEXT NOT NULL,
                kind                TEXT,
                total_bytes         INTEGER DEFAULT 0,
                local_bytes         INTEGER DEFAULT 0,
                cloud_bytes         INTEGER DEFAULT 0,
                vm_bytes            INTEGER DEFAULT 0,
                server_bytes        INTEGER DEFAULT 0,
                workstation_bytes   INTEGER DEFAULT 0,
                m365_bytes          INTEGER DEFAULT 0,
                quota_bytes         INTEGER,
                usage_percent       REAL DEFAULT 0.0,
                updated_at          TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tenant_storage_name ON tenant_storage(tenant_name);
        """)

    # Migraciones en caliente
    with get_conn() as conn:
        try:
            conn.execute("ALTER TABLE machines ADD COLUMN notify_telegram INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE machines ADD COLUMN muted_until TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE machines ADD COLUMN tags TEXT DEFAULT '[]'")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE machines ADD COLUMN last_backup_success_notified TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE backup_executions ADD COLUMN storage_target TEXT DEFAULT 'cloud_acronis'")
        except sqlite3.OperationalError:
            pass

    print(f"[DB] Base de datos inicializada en: {DB_PATH}")

# ─────────────────────────── Máquinas ──────────────────────────────────────

def upsert_machine(vm: dict, now: str) -> List[dict]:
    """
    Inserta o actualiza una máquina.
    Detecta cambios y devuelve la lista de cambios encontrados.
    """
    changes = []
    alerts_json = json.dumps(vm.get('alerts', []))

    TRACKED_FIELDS = [
        'protection_status', 'cyberfit_score', 'agent_version',
        'protection_plan', 'last_backup_success', 'alerts'
    ]

    with get_conn() as conn:
        existing = conn.execute(
            "SELECT * FROM machines WHERE vm_id = ?", (vm['vm_id'],)
        ).fetchone()

        if existing:
            # Detectar qué campos cambiaron
            existing_alerts = existing['alerts'] or '[]'
            vm_data_flat = {
                'protection_status': vm.get('protection_status'),
                'cyberfit_score':    vm.get('cyberfit_score', 0),
                'agent_version':     vm.get('agent_version'),
                'protection_plan':   vm.get('protection_plan'),
                'last_backup_success': vm.get('last_backup_success'),
                'alerts':            alerts_json,
            }
            for field in TRACKED_FIELDS:
                old_val = str(existing[field]) if existing[field] is not None else None
                new_val = str(vm_data_flat[field]) if vm_data_flat[field] is not None else None

                if old_val != new_val:
                    # Determinar severidad del cambio
                    sev = 'info'
                    if field == 'protection_status' and new_val in ('critical', 'warning'):
                        sev = new_val
                    elif field == 'alerts' and len(vm.get('alerts', [])) > 0:
                        sev = 'warning'

                    changes.append({
                        'vm_id':        vm['vm_id'],
                        'vm_name':      vm.get('name'),
                        'tenant_name':  vm.get('tenant_name'),
                        'timestamp':    now,
                        'field_changed': field,
                        'old_value':    old_val,
                        'new_value':    new_val,
                        'severity':     sev
                    })

            # Actualizar estado actual (preservando agent_version y backup_size_gb si el nuevo viene vacío o en 0)
            conn.execute("""
                UPDATE machines SET
                    name=?, tenant_id=?, tenant_name=?,
                    agent_version = CASE WHEN ? IS NOT NULL AND ? != 'Unknown' THEN ? ELSE COALESCE(agent_version, 'Desconocido') END,
                    protection_plan=?, protection_status=?, cyberfit_score=?,
                    last_backup_success=?, next_backup=?,
                    backup_size_gb = CASE WHEN ? > 0 THEN ? ELSE COALESCE(backup_size_gb, 0) END,
                    last_antimalware=?, next_antimalware=?, alerts=?,
                    last_seen=?,
                    last_changed = CASE WHEN ? > 0 THEN ? ELSE last_changed END
                WHERE vm_id=?
            """, (
                vm.get('name'), vm.get('tenant_id'), vm.get('tenant_name'),
                vm.get('agent_version'), vm.get('agent_version'), vm.get('agent_version'),
                vm.get('protection_plan'), vm.get('protection_status'), vm.get('cyberfit_score', 0),
                vm.get('last_backup_success'), vm.get('next_backup'),
                vm.get('backup_size_gb', 0), vm.get('backup_size_gb', 0),
                vm.get('last_antimalware_scan'), vm.get('next_antimalware_scan'), alerts_json,
                now, len(changes), now, vm['vm_id']
            ))
        else:
            # Primera vez que vemos esta máquina
            conn.execute("""
                INSERT INTO machines (
                    vm_id, name, tenant_id, tenant_name, agent_version,
                    protection_plan, protection_status, cyberfit_score,
                    last_backup_success, next_backup, backup_size_gb,
                    last_antimalware, next_antimalware, alerts,
                    first_seen, last_seen, last_changed
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                vm['vm_id'], vm.get('name'), vm.get('tenant_id'),
                vm.get('tenant_name'), vm.get('agent_version'),
                vm.get('protection_plan'), vm.get('protection_status'),
                vm.get('cyberfit_score', 0), vm.get('last_backup_success'),
                vm.get('next_backup'), vm.get('backup_size_gb', 0),
                vm.get('last_antimalware_scan'), vm.get('next_antimalware_scan'),
                alerts_json, now, now, now
            ))
            changes.append({
                'vm_id':        vm['vm_id'],
                'vm_name':      vm.get('name'),
                'tenant_name':  vm.get('tenant_name'),
                'timestamp':    now,
                'field_changed': 'NUEVO_EQUIPO',
                'old_value':    None,
                'new_value':    vm.get('protection_status'),
                'severity':     'info'
            })

        # Guardar cambios en historial
        if changes:
            conn.executemany("""
                INSERT INTO history (vm_id, vm_name, tenant_name, timestamp,
                    field_changed, old_value, new_value, severity)
                VALUES (:vm_id, :vm_name, :tenant_name, :timestamp,
                    :field_changed, :old_value, :new_value, :severity)
            """, changes)

    return changes


def get_all_machines() -> List[dict]:
    """Devuelve todas las máquinas con su estado actual."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM machines ORDER BY pinned DESC, dashboard_order ASC, name ASC
        """).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d['alerts'] = json.loads(d.get('alerts') or '[]')
            result.append(d)
        return result


def get_machines_for_dashboard() -> List[dict]:
    """Solo las máquinas marcadas como visibles."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM machines WHERE visible=1
            ORDER BY pinned DESC, dashboard_order ASC, name ASC
        """).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d['alerts'] = json.loads(d.get('alerts') or '[]')
            result.append(d)
        return result


def set_machine_visibility(vm_id: str, visible: bool, pinned: bool = None, notify: bool = None, muted_until: str = None):
    with get_conn() as conn:
        if pinned is not None:
            conn.execute(
                "UPDATE machines SET visible=?, pinned=? WHERE vm_id=?",
                (1 if visible else 0, 1 if pinned else 0, vm_id)
            )
        else:
            conn.execute(
                "UPDATE machines SET visible=? WHERE vm_id=?",
                (1 if visible else 0, vm_id)
            )
        if notify is not None:
            conn.execute(
                "UPDATE machines SET notify_telegram=? WHERE vm_id=?",
                (1 if notify else 0, vm_id)
            )
        if muted_until is not None:
            conn.execute(
                "UPDATE machines SET muted_until=? WHERE vm_id=?",
                (muted_until, vm_id)
            )


def set_backup_success_notified(vm_id: str, timestamp_iso: str):
    """Guarda el timestamp del último respaldo exitoso notificado para evitar notificaciones duplicadas."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE machines SET last_backup_success_notified=? WHERE vm_id=?",
            (timestamp_iso, vm_id)
        )


def set_bulk_notifications(notify: bool, tenant_id: str = None):
    """Activa o desactiva alertas masivamente."""
    with get_conn() as conn:
        q = "UPDATE machines SET notify_telegram = ?"
        params = [1 if notify else 0]
        if tenant_id:
            q += " WHERE tenant_id = ?"
            params.append(tenant_id)
        conn.execute(q, params)


def set_bulk_visibility(visible: bool, tenant_id: str = None):
    """Muestra u oculta equipos masivamente."""
    with get_conn() as conn:
        q = "UPDATE machines SET visible = ?"
        params = [1 if visible else 0]
        if tenant_id:
            q += " WHERE tenant_id = ?"
            params.append(tenant_id)
        conn.execute(q, params)

# ─────────────────────────── Historial ────────────────────────────────────

def get_history(vm_id: str = None, limit: int = 100, severity: str = None) -> List[dict]:
    """Obtiene el historial de cambios. Filtra por VM y/o severidad."""
    filters = []
    params = []

    if vm_id:
        filters.append("vm_id = ?")
        params.append(vm_id)
    if severity:
        filters.append("severity = ?")
        params.append(severity)

    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM history {where} ORDER BY timestamp DESC LIMIT ?",
            params
        ).fetchall()
        return [dict(r) for r in rows]


def get_history_summary() -> dict:
    """Resumen del historial: total cambios, por severidad, últimas 24h."""
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM history WHERE severity='critical'"
        ).fetchone()[0]
        warning = conn.execute(
            "SELECT COUNT(*) FROM history WHERE severity='warning'"
        ).fetchone()[0]
        last_24h = conn.execute(
            "SELECT COUNT(*) FROM history WHERE timestamp > datetime('now', '-1 day')"
        ).fetchone()[0]
        return {
            'total': total,
            'critical': critical,
            'warning': warning,
            'last_24h': last_24h
        }

# ─────────────────────────── Config Dashboard ──────────────────────────────

def get_config(key: str, default=None):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM dashboard_config WHERE key=?", (key,)
        ).fetchone()
        if row:
            try:
                return json.loads(row['value'])
            except Exception:
                return row['value']
        return default


def set_config(key: str, value):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO dashboard_config (key, value) VALUES (?,?)",
            (key, json.dumps(value))
        )

# ─────────────────────── Config de Canales de Notificación ────────────────

_CHANNEL_DEFAULTS = {
    'telegram': {
        'enabled':   False,
        'bot_token': '',
        'chat_ids':  [],    # lista de strings
    },
    'email': {
        'enabled':     False,
        'smtp_host':   '',
        'smtp_port':   587,
        'smtp_user':   '',
        'smtp_pass':   '',   # se omite al devolver al frontend
        'from_email':  '',
        'to_emails':   [],   # lista de strings
        'use_tls':     True,
    }
}

def get_channel_config(channel: str) -> dict:
    """Retorna la config de un canal (telegram | email). Nunca devuelve None."""
    raw = get_config(f'channel_{channel}')
    default = dict(_CHANNEL_DEFAULTS.get(channel, {}))
    if raw and isinstance(raw, dict):
        default.update(raw)
    return default

def set_channel_config(channel: str, data: dict):
    """Guarda la config de un canal. Hace merge con los defaults."""
    current = get_channel_config(channel)
    current.update(data)
    set_config(f'channel_{channel}', current)

def get_channel_config_safe(channel: str) -> dict:
    """Igual que get_channel_config pero oculta smtp_pass para el frontend."""
    cfg = dict(get_channel_config(channel))
    if 'smtp_pass' in cfg:
        cfg['smtp_pass'] = '●●●●●●' if cfg['smtp_pass'] else ''
    return cfg

# ─────────────────────── Notificaciones (anti-spam) ───────────────────────

def get_active_notification(vm_id: str, alert_type: str) -> Optional[dict]:
    """Busca una notificación activa (no resuelta) para esta VM + tipo de alerta."""
    with get_conn() as conn:
        row = conn.execute(
            """SELECT * FROM notifications_sent
               WHERE vm_id=? AND alert_type=? AND resolved_at IS NULL""",
            (vm_id, alert_type)
        ).fetchone()
        return dict(row) if row else None


def upsert_notification(vm_id: str, vm_name: str, tenant_name: str,
                        alert_type: str, severity: str, now: str,
                        extra_data: dict = None) -> dict:
    """
    Crea o actualiza una notificación activa.
    - Si no existe: la crea (first_sent=now, send_count=1).
    - Si existe y resolved_at IS NULL: incrementa send_count y last_sent.
    Devuelve {'action': 'created'|'updated', 'send_count': N, 'first_sent': ISO}.
    """
    extra_json = json.dumps(extra_data or {})
    existing = get_active_notification(vm_id, alert_type)

    with get_conn() as conn:
        if existing:
            conn.execute("""
                UPDATE notifications_sent
                SET last_sent=?, send_count=send_count+1, severity=?,
                    vm_name=?, tenant_name=?, extra_data=?
                WHERE id=?
            """, (now, severity, vm_name, tenant_name, extra_json, existing['id']))
            return {
                'action':      'updated',
                'send_count':  existing['send_count'] + 1,
                'first_sent':  existing['first_sent'],
                'id':          existing['id']
            }
        else:
            cursor = conn.execute("""
                INSERT INTO notifications_sent
                    (vm_id, vm_name, tenant_name, alert_type, severity,
                     first_sent, last_sent, send_count, extra_data)
                VALUES (?,?,?,?,?,?,?,1,?)
            """, (vm_id, vm_name, tenant_name, alert_type, severity,
                  now, now, extra_json))
            return {
                'action':      'created',
                'send_count':  1,
                'first_sent':  now,
                'id':          cursor.lastrowid
            }


def resolve_notification(vm_id: str, alert_type: str, now: str) -> bool:
    """
    Marca como resuelta una notificación activa.
    Devuelve True si había una activa para resolver.
    """
    existing = get_active_notification(vm_id, alert_type)
    if not existing:
        return False
    with get_conn() as conn:
        conn.execute(
            "UPDATE notifications_sent SET resolved_at=? WHERE id=?",
            (now, existing['id'])
        )
    return True


def get_active_notifications(severity: str = None) -> List[dict]:
    """Lista todas las notificaciones activas (no resueltas, no acknowledged)."""
    with get_conn() as conn:
        q = """SELECT n.*, m.protection_status, m.cyberfit_score
               FROM notifications_sent n
               LEFT JOIN machines m ON n.vm_id = m.vm_id
               WHERE n.resolved_at IS NULL AND n.acknowledged = 0"""
        params = []
        if severity:
            q += " AND n.severity = ?"
            params.append(severity)
        q += " ORDER BY n.last_sent DESC"
        rows = conn.execute(q, params).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d['extra_data'] = json.loads(d.get('extra_data') or '{}')
            result.append(d)
        return result


def acknowledge_notification(notif_id: int) -> bool:
    """Marca una notificación como atendida (acknowledged) desde el dashboard."""
    with get_conn() as conn:
        r = conn.execute(
            "UPDATE notifications_sent SET acknowledged=1 WHERE id=?", (notif_id,)
        )
        return r.rowcount > 0


def get_notifications_summary() -> dict:
    """Resumen de notificaciones activas para el dashboard."""
    with get_conn() as conn:
        active = conn.execute(
            "SELECT COUNT(*) FROM notifications_sent WHERE resolved_at IS NULL"
        ).fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM notifications_sent WHERE resolved_at IS NULL AND severity='critical'"
        ).fetchone()[0]
        warning = conn.execute(
            "SELECT COUNT(*) FROM notifications_sent WHERE resolved_at IS NULL AND severity='warning'"
        ).fetchone()[0]
        resolved_24h = conn.execute(
            """SELECT COUNT(*) FROM notifications_sent
               WHERE resolved_at > datetime('now', '-1 day')"""
        ).fetchone()[0]
        return {
            'active': active, 'critical': critical,
            'warning': warning, 'resolved_24h': resolved_24h
        }


# ─────────────────────── Histórico de Ejecuciones (Activities) ─────────────

def insert_backup_execution(data: dict) -> bool:
    """
    Inserta una ejecución de backup desde Task Manager API / Activities.
    Deduplica por activity_id. Devuelve True si se insertó un nuevo registro.
    """
    with get_conn() as conn:
        cursor = conn.execute("""
            INSERT OR IGNORE INTO backup_executions (
                activity_id, vm_id, vm_name, tenant_id, tenant_name,
                plan_name, start_time, end_time, duration_seconds,
                result, error_message, size_bytes, storage_target, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('activity_id'),
            data.get('vm_id'),
            data.get('vm_name'),
            data.get('tenant_id'),
            data.get('tenant_name'),
            data.get('plan_name'),
            data.get('start_time'),
            data.get('end_time'),
            data.get('duration_seconds', 0),
            data.get('result', 'success'),
            data.get('error_message'),
            data.get('size_bytes', 0),
            data.get('storage_target', 'cloud_acronis'),
            data.get('created_at', datetime.now(timezone.utc).isoformat())
        ))
        return cursor.rowcount > 0


def insert_storage_snapshot(data: dict) -> int:
    """
    Registra una muestra de capacidad de almacenamiento (NTFS o Cloud).
    """
    with get_conn() as conn:
        cursor = conn.execute("""
            INSERT INTO storage_history (
                tenant_id, tenant_name, storage_name, storage_type,
                total_bytes, used_bytes, free_bytes, usage_percent, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get('tenant_id'),
            data.get('tenant_name'),
            data.get('storage_name'),
            data.get('storage_type', 'local_ntfs'),
            data.get('total_bytes', 0),
            data.get('used_bytes', 0),
            data.get('free_bytes', 0),
            data.get('usage_percent', 0.0),
            data.get('timestamp', datetime.now(timezone.utc).isoformat())
        ))
        return cursor.lastrowid


def get_latest_storage_metrics() -> List[dict]:
    """
    Retorna la medición más reciente para cada almacenamiento registrado.
    """
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT s.*
            FROM storage_history s
            INNER JOIN (
                SELECT storage_name, MAX(timestamp) as max_ts
                FROM storage_history
                GROUP BY storage_name
            ) latest ON s.storage_name = latest.storage_name AND s.timestamp = latest.max_ts
            ORDER BY s.storage_type ASC, s.storage_name ASC
        """).fetchall()
        return [dict(r) for r in rows]


def get_backup_metrics(start_iso: str, end_iso: str, tenant_id: str = None, vm_ids: list = None) -> dict:
    """
    Calcula métricas agregadas de respaldos entre dos fechas (ISO) para el reporte,
    con soporte para filtrar por lista de máquinas seleccionadas (vm_ids).
    """
    where_clauses = ["created_at >= ?", "created_at <= ?"]
    params = [start_iso, end_iso]

    if tenant_id:
        where_clauses.append("tenant_id = ?")
        params.append(tenant_id)

    if vm_ids and len(vm_ids) > 0:
        placeholders = ','.join('?' for _ in vm_ids)
        where_clauses.append(f"vm_id IN ({placeholders})")
        params.extend(vm_ids)

    where_sql = " AND ".join(where_clauses)

    with get_conn() as conn:
        # 1. Conteo de ejecuciones y métricas de volumen/duración
        counts = conn.execute(f"""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) as success,
                SUM(CASE WHEN result = 'warning' THEN 1 ELSE 0 END) as warning,
                SUM(CASE WHEN result = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(size_bytes) as total_size_bytes,
                AVG(duration_seconds) as avg_duration_seconds,
                SUM(duration_seconds) as total_duration_seconds
            FROM backup_executions
            WHERE {where_sql}
        """, params).fetchone()

        total = counts['total'] or 0
        success = counts['success'] or 0
        warning = counts['warning'] or 0
        failed = counts['failed'] or 0
        rate = round((success / total * 100.0), 1) if total > 0 else 100.0

        total_bytes = counts['total_size_bytes'] or 0
        avg_duration = round(counts['avg_duration_seconds'] or 0)
        total_duration = round(counts['total_duration_seconds'] or 0)

        # 2. Máquinas con problemas en el período
        affected_rows = conn.execute(f"""
            SELECT vm_id, vm_name, tenant_name, plan_name, result, error_message, end_time, created_at
            FROM backup_executions
            WHERE {where_sql} AND result IN ('failed', 'warning')
            ORDER BY created_at DESC
        """, params).fetchall()

        affected = [dict(r) for r in affected_rows]

        # 3. Equipos seleccionados y sus estados
        if vm_ids and len(vm_ids) > 0:
            m_placeholders = ','.join('?' for _ in vm_ids)
            m_query = f"SELECT * FROM machines WHERE vm_id IN ({m_placeholders})"
            m_params = list(vm_ids)
            if tenant_id:
                m_query += " AND tenant_id = ?"
                m_params.append(tenant_id)
            m_query += " ORDER BY name ASC"
        else:
            m_query = "SELECT * FROM machines WHERE visible=1"
            m_params = []
            if tenant_id:
                m_query += " AND tenant_id = ?"
                m_params.append(tenant_id)
            m_query += " ORDER BY name ASC"

        machines_rows = conn.execute(m_query, m_params).fetchall()
        machines = []
        for r in machines_rows:
            m = dict(r)

            # Conteo de respaldos realizados por esta máquina en el período
            exec_stats = conn.execute(f"""
                SELECT 
                    COUNT(*) as total_backups,
                    SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) as success_runs,
                    SUM(CASE WHEN result = 'warning' THEN 1 ELSE 0 END) as warning_runs,
                    SUM(CASE WHEN result = 'failed' THEN 1 ELSE 0 END) as failed_runs
                FROM backup_executions
                WHERE (vm_id = ? OR vm_name = ?) AND created_at >= ? AND created_at <= ?
            """, (m['vm_id'], m['name'], start_iso, end_iso)).fetchone()

            tot_b = exec_stats['total_backups'] or 0
            succ_b = exec_stats['success_runs'] or 0
            warn_b = exec_stats['warning_runs'] or 0
            fail_b = exec_stats['failed_runs'] or 0

            # Si no hay ejecuciones registradas en la tabla pero tiene last_backup_success en el período
            if tot_b == 0 and m.get('last_backup_success'):
                lb = m.get('last_backup_success')
                if start_iso <= lb <= end_iso:
                    tot_b = 1
                    if m.get('protection_status') == 'critical':
                        fail_b = 1
                    elif m.get('protection_status') == 'warning':
                        warn_b = 1
                    else:
                        succ_b = 1

            m['backup_count'] = tot_b
            m['backup_count_success'] = succ_b
            m['backup_count_warning'] = warn_b
            m['backup_count_failed'] = fail_b

            if tot_b > 0:
                parts = []
                if succ_b > 0: parts.append(f"{succ_b} ✅")
                if warn_b > 0: parts.append(f"{warn_b} ⚠️")
                if fail_b > 0: parts.append(f"{fail_b} 🔴")
                m['backup_count_str'] = f"{tot_b} ({', '.join(parts)})"
            else:
                m['backup_count_str'] = "0"

            # Buscar última ejecución registrada para enriquecer con duración, tamaño y destino
            latest_exec = conn.execute("""
                SELECT duration_seconds, size_bytes, result, error_message, end_time, storage_target
                FROM backup_executions
                WHERE vm_id = ? OR vm_name = ?
                ORDER BY created_at DESC LIMIT 1
            """, (m['vm_id'], m['name'])).fetchone()

            plan_str = (m.get('protection_plan') or '').lower()
            has_local_plan = any(k in plan_str for k in ('[local]', 'local', 'ntfs', 'smb', 'disco local', 'carpeta local'))
            has_cloud_plan = any(k in plan_str for k in ('cloud', 'acronis')) or (';' in plan_str and has_local_plan) or (not has_local_plan)

            exec_target = latest_exec['storage_target'] if latest_exec and latest_exec['storage_target'] else None
            if exec_target == 'local_ntfs':
                has_local_plan = True

            raw_sz = latest_exec['size_bytes'] if latest_exec and latest_exec['size_bytes'] else int((m.get('backup_size_gb') or 0) * (1024**3))

            m['latest_duration_seconds'] = latest_exec['duration_seconds'] if latest_exec else 0
            m['latest_size_bytes'] = raw_sz
            m['latest_result'] = latest_exec['result'] if latest_exec else ('success' if m.get('protection_status') != 'critical' else 'warning')
            m['latest_error'] = latest_exec['error_message'] if latest_exec else None

            if has_local_plan and has_cloud_plan:
                m['storage_target'] = 'hybrid'
                m['latest_local_bytes'] = raw_sz
                m['latest_cloud_bytes'] = raw_sz
            elif has_local_plan:
                m['storage_target'] = 'local_ntfs'
                m['latest_local_bytes'] = raw_sz
                m['latest_cloud_bytes'] = 0
            else:
                m['storage_target'] = 'cloud_acronis'
                m['latest_cloud_bytes'] = raw_sz
                m['latest_local_bytes'] = 0

            machines.append(m)

        # Si no hubo ejecuciones directas en backup_executions para total_bytes, sumar desde machines
        if total_bytes == 0 and len(machines) > 0:
            total_bytes = sum(m.get('latest_size_bytes', 0) for m in machines)

        # Distribución de planes
        plans_dist = {}
        for m in machines:
            p = m.get('protection_plan') or 'Sin Plan'
            plans_dist[p] = plans_dist.get(p, 0) + 1

        return {
            'total_executions': total,
            'success_count': success,
            'warning_count': warning,
            'failed_count': failed,
            'success_rate': rate,
            'total_size_bytes': total_bytes,
            'avg_duration_seconds': avg_duration,
            'total_duration_seconds': total_duration,
            'affected_machines': affected,
            'total_machines': len(machines),
            'plans_distribution': plans_dist,
            'machines': machines
        }


# ─────────────────────── Configuración del Reporte ─────────────────────────

_REPORT_DEFAULTS = {
    'enabled': True,
    'day_of_week': 'mon',              # mon, tue, wed, thu, fri, sat, sun
    'time_utc4': '08:00',              # HH:MM en hora de Chile
    'emails': ['francisco@minio.cl', 'pablo@minio.cl'],
    'selected_vm_ids': [],             # Lista de IDs específicos (vacío = máquinas visibles en dashboard)
    'local_warn_pct': 85,
    'cloud_warn_pct': 90,
    'last_sent_date': ''               # YYYY-MM-DD para evitar duplicar envío
}

def get_report_config() -> dict:
    raw = get_config('weekly_report_config')
    cfg = dict(_REPORT_DEFAULTS)
    if raw and isinstance(raw, dict):
        cfg.update(raw)
    return cfg

def set_report_config(data: dict) -> dict:
    current = get_report_config()
    current.update(data)
    set_config('weekly_report_config', current)
    return current


# ────────────────── Almacenamiento & Cuotas por Tenant ──────────────────────

def upsert_tenant_storage(record: dict) -> bool:
    """Inserta o actualiza el registro de almacenamiento y cuota de un tenant/cliente."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO tenant_storage (
                tenant_id, tenant_name, kind, total_bytes, local_bytes, cloud_bytes,
                vm_bytes, server_bytes, workstation_bytes, m365_bytes,
                quota_bytes, usage_percent, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
                tenant_name = excluded.tenant_name,
                kind = excluded.kind,
                total_bytes = excluded.total_bytes,
                local_bytes = excluded.local_bytes,
                cloud_bytes = excluded.cloud_bytes,
                vm_bytes = excluded.vm_bytes,
                server_bytes = excluded.server_bytes,
                workstation_bytes = excluded.workstation_bytes,
                m365_bytes = excluded.m365_bytes,
                quota_bytes = excluded.quota_bytes,
                usage_percent = excluded.usage_percent,
                updated_at = excluded.updated_at
        """, (
            record.get('tenant_id'),
            record.get('tenant_name', 'Cliente Desconocido'),
            record.get('kind', 'customer'),
            int(record.get('total_bytes') or 0),
            int(record.get('local_bytes') or 0),
            int(record.get('cloud_bytes') or 0),
            int(record.get('vm_bytes') or 0),
            int(record.get('server_bytes') or 0),
            int(record.get('workstation_bytes') or 0),
            int(record.get('m365_bytes') or 0),
            int(record.get('quota_bytes')) if record.get('quota_bytes') is not None else None,
            float(record.get('usage_percent') or 0.0),
            record.get('updated_at') or now_iso
        ))
        return True


def get_all_tenant_storages() -> list[dict]:
    """Retorna todos los tenants con sus métricas de almacenamiento y cuota."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM tenant_storage
            ORDER BY total_bytes DESC, tenant_name ASC
        """).fetchall()
        return [dict(r) for r in rows]


def get_global_storage_summary() -> dict:
    """Calcula totales acumulados de almacenamiento de todos los clientes."""
    with get_conn() as conn:
        totals = conn.execute("""
            SELECT 
                COUNT(*) as total_tenants,
                SUM(total_bytes) as total_storage_bytes,
                SUM(local_bytes) as total_local_bytes,
                SUM(cloud_bytes) as total_cloud_bytes,
                SUM(vm_bytes) as total_vm_bytes,
                SUM(server_bytes) as total_server_bytes,
                SUM(workstation_bytes) as total_workstation_bytes,
                SUM(m365_bytes) as total_m365_bytes,
                SUM(CASE WHEN quota_bytes IS NOT NULL THEN quota_bytes ELSE 0 END) as total_quota_bytes
            FROM tenant_storage
        """).fetchone()

        return {
            'total_tenants': totals['total_tenants'] or 0,
            'total_storage_bytes': totals['total_storage_bytes'] or 0,
            'total_local_bytes': totals['total_local_bytes'] or 0,
            'total_cloud_bytes': totals['total_cloud_bytes'] or 0,
            'total_vm_bytes': totals['total_vm_bytes'] or 0,
            'total_server_bytes': totals['total_server_bytes'] or 0,
            'total_workstation_bytes': totals['total_workstation_bytes'] or 0,
            'total_m365_bytes': totals['total_m365_bytes'] or 0,
            'total_quota_bytes': totals['total_quota_bytes'] or 0
        }

