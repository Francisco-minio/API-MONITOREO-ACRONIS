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
                last_changed        TEXT                -- última vez que algo cambió
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

            CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_vm_type
                ON notifications_sent(vm_id, alert_type)
                WHERE resolved_at IS NULL;   -- solo una alerta activa por tipo/VM
        """)
    with get_conn() as conn:
        # Tables...
        conn.executescript("""
            -- (Misma lógica de creación que ya existe)
        """)
        
        # Migración: asegurar que existe notify_telegram
        try:
            conn.execute("ALTER TABLE machines ADD COLUMN notify_telegram INTEGER DEFAULT 0")
            print("[DB] Columna notify_telegram agregada exitosamente")
        except sqlite3.OperationalError:
            pass # Ya existe
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

            # Actualizar estado actual
            conn.execute("""
                UPDATE machines SET
                    name=?, tenant_id=?, tenant_name=?, agent_version=?,
                    protection_plan=?, protection_status=?, cyberfit_score=?,
                    last_backup_success=?, next_backup=?, backup_size_gb=?,
                    last_antimalware=?, next_antimalware=?, alerts=?,
                    last_seen=?,
                    last_changed = CASE WHEN ? > 0 THEN ? ELSE last_changed END
                WHERE vm_id=?
            """, (
                vm.get('name'), vm.get('tenant_id'), vm.get('tenant_name'),
                vm.get('agent_version'), vm.get('protection_plan'),
                vm.get('protection_status'), vm.get('cyberfit_score', 0),
                vm.get('last_backup_success'), vm.get('next_backup'),
                vm.get('backup_size_gb', 0), vm.get('last_antimalware_scan'),
                vm.get('next_antimalware_scan'), alerts_json,
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


def set_machine_visibility(vm_id: str, visible: bool, pinned: bool = None, notify: bool = None):
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
