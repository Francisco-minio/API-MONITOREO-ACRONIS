"""
notification_engine.py  — Motor de Notificaciones Acronis VM Monitor

Fuentes de alertas (enfoque híbrido):
  1. Reglas propias sobre datos en DB  → backup >25h/48h, CyberFit bajo,
                                          estado critical/warning
  2. API nativa de Acronis              → alertas de bajo nivel (amenazas,
                                          agente offline, licencias)

Anti-spam (tabla notifications_sent):
  - Solo envía si la condición apareció por primera vez, O
  - Si escaló de severidad (>25h → >48h), O
  - Si se cumplió el intervalo de re-notificación (REMIND_INTERVAL_H)
  - Envía resolución cuando la condición desaparece

Canales soportados: Telegram (extensible a Email en Etapa 3)

Variables de entorno requeridas:
  TELEGRAM_BOT_TOKEN   — token del bot
  TELEGRAM_CHAT_ID     — chat/grupo destino (puede ser lista separada por coma)

Variables opcionales:
  NOTIFY_INTERVAL_SECONDS  (default 300) — cada cuánto corre el engine
  REMIND_INTERVAL_H        (default 6)   — re-notificar si sigue igual (horas)
  NOTIFY_BACKUP_HOURS      (default 25)  — umbral backup warning
  NOTIFY_BACKUP_CRIT_HOURS (default 48)  — umbral backup critical
  CYBERFIT_THRESHOLD       (default 500) — umbral score
  ACRONIS_ALERTS_ENABLED   (default true) — activar fuente API de Acronis
  DRY_RUN                  (default false) — simular sin enviar
"""

import os
import sys
import time
import json
import requests
from typing import Optional, Tuple
from datetime import datetime, timezone, timedelta
from base64 import b64encode
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import acronis_db as db

load_dotenv()

# ─────────────────────────── Configuración ─────────────────────────────────

TELEGRAM_BOT_TOKEN    = os.getenv('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_IDS     = [c.strip() for c in os.getenv('TELEGRAM_CHAT_ID', '').split(',') if c.strip()]

CLIENT_ID             = os.getenv('ACRONIS_CLIENT_ID', '')
CLIENT_SECRET         = os.getenv('ACRONIS_CLIENT_SECRET', '')
DC_URL                = os.getenv('ACRONIS_DC_URL', 'https://us5-cloud.acronis.com').rstrip('/')

NOTIFY_INTERVAL       = int(os.getenv('NOTIFY_INTERVAL_SECONDS', 300))
REMIND_INTERVAL_H     = int(os.getenv('REMIND_INTERVAL_H', 6))
BACKUP_WARN_H         = int(os.getenv('NOTIFY_BACKUP_HOURS', 25))
BACKUP_CRIT_H         = int(os.getenv('NOTIFY_BACKUP_CRIT_HOURS', 48))
CYBERFIT_THR          = int(os.getenv('CYBERFIT_THRESHOLD', 500))
ACRONIS_ALERTS_ON     = os.getenv('ACRONIS_ALERTS_ENABLED', 'true').lower() == 'true'
DRY_RUN               = os.getenv('DRY_RUN', 'false').lower() == 'true'

# ─────────────────────────── Tipos de alerta ───────────────────────────────

class AlertType:
    BACKUP_NO_RECORD   = 'BACKUP_NO_RECORD'    # nunca hizo backup
    BACKUP_WARN        = 'BACKUP_OVERDUE_25H'  # >25h sin backup
    BACKUP_CRIT        = 'BACKUP_OVERDUE_48H'  # >48h sin backup
    CYBERFIT_LOW       = 'CYBERFIT_LOW'
    STATUS_CRITICAL    = 'STATUS_CRITICAL'
    STATUS_WARNING     = 'STATUS_WARNING'
    AM_OVERDUE         = 'ANTIMALWARE_OVERDUE'
    # Alertas nativas Acronis
    ACRONIS_NATIVE     = 'ACRONIS_NATIVE'


# ─────────────────────────── Telegram ──────────────────────────────────────

def send_telegram(message: str, force_cfg: dict = None) -> bool:
    """Envía mensaje a todos los chats configurados en DB."""
    if DRY_RUN:
        print(f"[DRY_RUN] Telegram:\n{message}\n")
        return True

    # Obtener config de la DB si no se pasa explícitamente
    cfg = force_cfg or db.get_channel_config('telegram')
    token    = cfg.get('bot_token')
    chat_ids = cfg.get('chat_ids', [])

    if not cfg.get('enabled'):
        return False

    if not token or not chat_ids:
        print("[WARN] Telegram habilitado pero no configurado (Token/Chat IDs vacíos)")
        return False

    success = True
    for chat_id in chat_ids:
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    'chat_id':    chat_id,
                    'text':       message,
                    'parse_mode': 'HTML'
                },
                timeout=15
            )
            if not r.ok:
                print(f"[TELEGRAM ERROR] chat {chat_id}: {r.status_code} {r.text[:200]}")
                success = False
        except Exception as e:
            print(f"[TELEGRAM ERROR] {e}")
            success = False
    return success


def now_chile() -> datetime:
    """Retorna la hora actual en Chile (UTC-4)."""
    return datetime.now(timezone(timedelta(hours=-4)))


def fmt_ts(iso: Optional[str]) -> str:
    if not iso:
        return "Nunca"
    try:
        # Chile is UTC-4/-3. Let's use fixed -4 as standard for now, 
        # or use ZoneInfo if we want to be professional (requires tzdata).
        # We'll use a timedelta offset of -4 for simplicity in 3.9.6.
        tz_chile = timezone(timedelta(hours=-4))
        dt = datetime.fromisoformat(iso.replace('Z', '+00:00'))
        dt_local = dt.astimezone(tz_chile)
        return dt_local.strftime('%d/%m/%Y %H:%M')
    except Exception:
        return iso


def hours_since(iso: Optional[str]) -> Optional[float]:
    if not iso:
        return None
    try:
        dt  = datetime.fromisoformat(iso.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        return (now - dt).total_seconds() / 3600
    except Exception:
        return None


# ─────────────────────────── Mensajes Telegram ─────────────────────────────

def msg_backup_warn(vm: dict, hours: float, escalated: bool = False) -> str:
    sev_icon = "🔴" if hours >= BACKUP_CRIT_H else "🟡"
    sev_text = "CRÍTICO" if hours >= BACKUP_CRIT_H else "ADVERTENCIA"
    esc_tag  = " ⚠️ <b>ESCALADO</b>" if escalated else ""
    return (
        f"{sev_icon} <b>BACKUP {sev_text}{esc_tag}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥️  <b>{vm['name']}</b>\n"
        f"🏢 {vm.get('tenant_name','')}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⏱️  Sin backup hace: <b>{hours:.0f} horas</b>\n"
        f"📅 Último backup: {fmt_ts(vm.get('last_backup_success'))}\n"
        f"📋 Plan: {vm.get('protection_plan','N/A')}\n"
        f"🔒 Estado: {vm.get('protection_status','unknown').upper()}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 {now_chile().strftime('%d/%m/%Y %H:%M')}"
    )


def msg_backup_no_record(vm: dict) -> str:
    return (
        f"⚫ <b>SIN REGISTRO DE BACKUP</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥️  <b>{vm['name']}</b>\n"
        f"🏢 {vm.get('tenant_name','')}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"❌ Este equipo nunca ha registrado un backup exitoso.\n"
        f"📋 Plan: {vm.get('protection_plan','Sin Plan')}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 {now_chile().strftime('%d/%m/%Y %H:%M')}"
    )


def msg_cyberfit(vm: dict) -> str:
    score = vm.get('cyberfit_score', 0)
    return (
        f"🛡️ <b>CYBERFIT SCORE BAJO</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥️  <b>{vm['name']}</b>\n"
        f"🏢 {vm.get('tenant_name','')}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📊 Score actual: <b>{score} / 850</b>\n"
        f"⚠️  Umbral mínimo: {CYBERFIT_THR}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 {now_chile().strftime('%d/%m/%Y %H:%M')}"
    )


def msg_status(vm: dict) -> str:
    icon = "🔴" if vm.get('protection_status') == 'critical' else "🟡"
    return (
        f"{icon} <b>ESTADO DE PROTECCIÓN: {vm.get('protection_status','').upper()}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥️  <b>{vm['name']}</b>\n"
        f"🏢 {vm.get('tenant_name','')}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔒 Estado: <b>{vm.get('protection_status','').upper()}</b>\n"
        f"📋 Plan: {vm.get('protection_plan','N/A')}\n"
        f"📅 Último backup: {fmt_ts(vm.get('last_backup_success'))}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 {now_chile().strftime('%d/%m/%Y %H:%M')}"
    )


def msg_resolved(vm_name: str, tenant: str, alert_type: str, first_sent: str) -> str:
    labels = {
        AlertType.BACKUP_WARN:      'Backup sin ejecutar >25h',
        AlertType.BACKUP_CRIT:      'Backup sin ejecutar >48h',
        AlertType.BACKUP_NO_RECORD: 'Sin registro de backup',
        AlertType.CYBERFIT_LOW:     'CyberFit Score bajo',
        AlertType.STATUS_CRITICAL:  'Estado crítico',
        AlertType.STATUS_WARNING:   'Estado advertencia',
        AlertType.AM_OVERDUE:       'Antimalware vencido',
    }
    label = labels.get(alert_type, alert_type)
    return (
        f"✅ <b>ALERTA RESUELTA</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥️  <b>{vm_name}</b>  |  🏢 {tenant}\n"
        f"📌 {label}\n"
        f"🕐 Duración: desde {fmt_ts(first_sent)}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"✔️  {now_chile().strftime('%d/%m/%Y %H:%M')}"
    )


def msg_acronis_alert(alert: dict) -> str:
    sev   = alert.get('severity', 'info').upper()
    icon  = {'CRITICAL': '🔴', 'WARNING': '🟡', 'INFO': 'ℹ️'}.get(sev, '❕')
    atype = alert.get('type', 'N/A')
    rname = alert.get('details', {}).get('resource_name') or ''
    tname = alert.get('details', {}).get('tenant_name')   or ''
    desc  = alert.get('details', {}).get('description')   or atype
    return (
        f"{icon} <b>ALERTA ACRONIS — {sev}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥️  {rname or 'N/A'}\n"
        f"🏢 {tname}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📋 Tipo: <code>{atype}</code>\n"
        f"📝 {desc}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 {now_chile().strftime('%d/%m/%Y %H:%M')}"
    )


# ─────────────────────────── Lógica de decisión ────────────────────────────

def should_send(vm_id: str, alert_type: str, new_severity: str, now_iso: str) -> Tuple[bool, bool]:
    """
    Decide si se debe enviar la notificación.
    Retorna (send: bool, escalated: bool).
    """
    existing = db.get_active_notification(vm_id, alert_type)

    if not existing:
        return True, False   # primera vez → enviar siempre

    # Escalación: pasó de warning a critical
    if existing['severity'] != new_severity and new_severity == 'critical':
        return True, True

    # Re-notificación por intervalo (REMIND_INTERVAL_H)
    h = hours_since(existing['last_sent'])
    if h is not None and h >= REMIND_INTERVAL_H:
        return True, False

    return False, False


# ─────────────────────────── Reglas propias ────────────────────────────────

def check_own_rules(machines: list, now_iso: str) -> int:
    """
    Evalúa las reglas sobre los datos de la DB y registra en DB siempre.
    Envía por Telegram SOLO si la VM tiene 'notify_telegram'=1.
    """
    sent = 0

    for vm in machines:
        vm_id   = vm.get('vm_id')
        vm_name = vm.get('name', vm_id)
        tenant  = vm.get('tenant_name', '')
        notify  = bool(vm.get('notify_telegram')) # Preferencia individual

        if not vm_id:
            continue

        # ── 1. Backup sin registro ──────────────────────────────────────────
        has_backup = bool(vm.get('last_backup_success'))
        has_plan   = vm.get('protection_plan') not in (None, '', 'Sin Plan', 'No plan')

        if not has_backup and has_plan:
            snd, esc = should_send(vm_id, AlertType.BACKUP_NO_RECORD, 'warning', now_iso)
            if snd:
                db.upsert_notification(vm_id, vm_name, tenant,
                                       AlertType.BACKUP_NO_RECORD, 'warning', now_iso)
                if notify:
                    send_telegram(msg_backup_no_record(vm))
                sent += 1
        else:
            if db.resolve_notification(vm_id, AlertType.BACKUP_NO_RECORD, now_iso):
                if notify:
                    send_telegram(msg_resolved(vm_name, tenant, AlertType.BACKUP_NO_RECORD, now_iso))

        # ── 2. Backup atrasado ──────────────────────────────────────────────
        hours = hours_since(vm.get('last_backup_success'))
        if hours is not None:
            if hours >= BACKUP_CRIT_H:
                snd, esc = should_send(vm_id, AlertType.BACKUP_CRIT, 'critical', now_iso)
                if snd:
                    db.upsert_notification(vm_id, vm_name, tenant,
                                           AlertType.BACKUP_CRIT, 'critical', now_iso,
                                           extra_data={'hours': round(hours, 1)})
                    if notify:
                        send_telegram(msg_backup_warn(vm, hours, escalated=esc))
                    sent += 1
                db.resolve_notification(vm_id, AlertType.BACKUP_WARN, now_iso)

            elif hours >= BACKUP_WARN_H:
                snd, esc = should_send(vm_id, AlertType.BACKUP_WARN, 'warning', now_iso)
                if snd:
                    db.upsert_notification(vm_id, vm_name, tenant,
                                           AlertType.BACKUP_WARN, 'warning', now_iso,
                                           extra_data={'hours': round(hours, 1)})
                    if notify:
                        send_telegram(msg_backup_warn(vm, hours))
                    sent += 1
            else:
                for atype in (AlertType.BACKUP_WARN, AlertType.BACKUP_CRIT):
                    existing = db.get_active_notification(vm_id, atype)
                    if existing and db.resolve_notification(vm_id, atype, now_iso):
                        if notify:
                            send_telegram(msg_resolved(vm_name, tenant, atype, existing['first_sent']))
                        sent += 1

        # ── 3. CyberFit bajo ───────────────────────────────────────────────
        score = int(vm.get('cyberfit_score') or 0)
        if score > 0 and score < CYBERFIT_THR:
            snd, _ = should_send(vm_id, AlertType.CYBERFIT_LOW, 'warning', now_iso)
            if snd:
                db.upsert_notification(vm_id, vm_name, tenant,
                                       AlertType.CYBERFIT_LOW, 'warning', now_iso,
                                       extra_data={'score': score})
                if notify:
                    send_telegram(msg_cyberfit(vm))
                sent += 1
        elif score >= CYBERFIT_THR:
            existing = db.get_active_notification(vm_id, AlertType.CYBERFIT_LOW)
            if existing and db.resolve_notification(vm_id, AlertType.CYBERFIT_LOW, now_iso):
                if notify:
                    send_telegram(msg_resolved(vm_name, tenant, AlertType.CYBERFIT_LOW, existing['first_sent']))
                sent += 1

        # ── 4. Estado crítico / warning ────────────────────────────────────
        pstatus = (vm.get('protection_status') or '').lower()
        for at, sev, st in [
            (AlertType.STATUS_CRITICAL, 'critical', 'critical'),
            (AlertType.STATUS_WARNING,  'warning',  'warning'),
        ]:
            if pstatus == st:
                snd, esc = should_send(vm_id, at, sev, now_iso)
                if snd:
                    db.upsert_notification(vm_id, vm_name, tenant, at, sev, now_iso)
                    if notify:
                        send_telegram(msg_status(vm))
                    sent += 1
            else:
                existing = db.get_active_notification(vm_id, at)
                if existing and db.resolve_notification(vm_id, at, now_iso):
                    if notify:
                        send_telegram(msg_resolved(vm_name, tenant, at, existing['first_sent']))
                    sent += 1

    return sent

# ─────────────────────── Alertas nativas Acronis ───────────────────────────

class AcronisAlertsClient:
    def __init__(self):
        self.token         = None
        self.token_expires = 0

    def ensure_token(self):
        if not self.token or time.time() >= self.token_expires:
            self._get_token()

    def _get_token(self):
        auth_str = f"{CLIENT_ID}:{CLIENT_SECRET}"
        encoded  = b64encode(auth_str.encode()).decode()
        r = requests.post(
            f"{DC_URL}/api/2/idp/token",
            headers={'Authorization': f'Basic {encoded}',
                     'Content-Type': 'application/x-www-form-urlencoded'},
            data={'grant_type': 'client_credentials'},
            timeout=30
        )
        r.raise_for_status()
        payload          = r.json()
        self.token       = payload.get('access_token')
        self.token_expires = time.time() + payload.get('expires_in', 3600) - 60

    def get_alerts(self, severity: str = None) -> list[dict]:
        """Obtiene alertas activas de la API de Acronis."""
        self.ensure_token()
        headers = {'Authorization': f'Bearer {self.token}'}
        params  = {'status': 'raised', 'limit': 200}
        if severity:
            params['severity'] = severity

        all_alerts = []
        cursor     = None
        while True:
            if cursor:
                params['after'] = cursor
            try:
                r = requests.get(
                    f"{DC_URL}/api/alert_manager/v1/alerts",
                    headers=headers, params=params, timeout=30
                )
                if r.status_code == 401:
                    self._get_token()
                    headers = {'Authorization': f'Bearer {self.token}'}
                    r = requests.get(f"{DC_URL}/api/alert_manager/v1/alerts",
                                     headers=headers, params=params, timeout=30)
                if r.status_code == 404:
                    print("[ACRONIS ALERTS] Endpoint no disponible en este tenant.")
                    break
                r.raise_for_status()
                data       = r.json()
                items      = data.get('items', [])
                all_alerts.extend(items)
                cursor     = data.get('paging', {}).get('cursors', {}).get('after')
                if not cursor or not items:
                    break
            except Exception as e:
                print(f"[ACRONIS ALERTS ERROR] {e}")
                break
        return all_alerts


_acronis_client = AcronisAlertsClient()

# Tipos de alertas nativas que queremos procesar (evitar ruido)
NATIVE_ALERT_TYPES = {
    'backup.machine_offline',
    'backup.failed',
    'antimalware.threat_detected',
    'antimalware.ransomware_detected',
    'license.expiring',
    'license.expired',
}

def check_acronis_alerts(now_iso: str) -> int:
    """
    Consulta las alertas nativas de Acronis y notifica por Telegram.
    Solo procesa tipos relevantes y aplica anti-spam.
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        return 0

    sent = 0
    try:
        alerts = _acronis_client.get_alerts()
        print(f"[ACRONIS NATIVE] {len(alerts)} alertas recibidas de la API")

        for alert in alerts:
            atype = alert.get('type', '')
            if atype not in NATIVE_ALERT_TYPES:
                continue

            # Usar el ID de alerta de Acronis como vm_id para el tracking
            alert_id  = alert.get('id', atype)
            sev_raw   = (alert.get('severity') or 'warning').lower()
            sev       = 'critical' if sev_raw in ('critical','high') else 'warning'

            # Construir clave única: tipo + recurso
            resource_id = (alert.get('details', {}).get('resource_id')
                           or alert.get('details', {}).get('context_id')
                           or alert_id)
            notif_key   = f"ACRONIS_{atype}_{resource_id}"

            snd, _ = should_send(resource_id, notif_key, sev, now_iso)
            if snd:
                if send_telegram(msg_acronis_alert(alert)):
                    db.upsert_notification(
                        resource_id,
                        alert.get('details', {}).get('resource_name', 'N/A'),
                        alert.get('details', {}).get('tenant_name', ''),
                        notif_key, sev, now_iso,
                        extra_data={'acronis_id': alert_id, 'type': atype}
                    )
                    sent += 1

    except Exception as e:
        print(f"[ACRONIS ALERTS ERROR] {e}")

    return sent


# ─────────────────────────── Ciclo principal ───────────────────────────────

def run():
    db.init_db()

    print(f"\n{'='*60}")
    print(f"  Acronis Notification Engine")
    print(f"  Intervalo      : {NOTIFY_INTERVAL}s")
    print(f"  Re-notificación: cada {REMIND_INTERVAL_H}h")
    print(f"  Backup warning : >{BACKUP_WARN_H}h  |  critical: >{BACKUP_CRIT_H}h")
    print(f"  CyberFit mín   : {CYBERFIT_THR}")
    print(f"  Telegram       : {'✅ configurado' if TELEGRAM_BOT_TOKEN else '❌ NO configurado'}")
    print(f"  Alertas Acronis: {'✅' if ACRONIS_ALERTS_ON else '❌'}")
    print(f"  DRY RUN        : {'✅ activo (no envía)' if DRY_RUN else '❌'}")
    print(f"{'='*60}\n")

    cycle = 0
    while True:
        cycle += 1
        now_iso = datetime.now(timezone.utc).isoformat()
        print(f"\n[CICLO {cycle}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            # 1. Obtener máquinas desde DB (sin llamar a Acronis)
            machines = db.get_all_machines()
            print(f"  Evaluando {len(machines)} máquinas (reglas propias)...")
            sent_own = check_own_rules(machines, now_iso)
            print(f"  → {sent_own} notificaciones propias enviadas")

            # 2. Alertas nativas de Acronis (fuente complementaria)
            if ACRONIS_ALERTS_ON and CLIENT_ID:
                print("  Consultando API de alertas de Acronis...")
                sent_native = check_acronis_alerts(now_iso)
                print(f"  → {sent_native} alertas nativas enviadas")

            # 3. Resumen de notificaciones activas
            summary = db.get_notifications_summary()
            print(f"  [RESUMEN] Activas: {summary['active']} "
                  f"(🔴 {summary['critical']} | 🟡 {summary['warning']}) "
                  f"| Resueltas hoy: {summary['resolved_24h']}")

        except Exception as e:
            import traceback
            print(f"[ERROR CICLO] {e}")
            traceback.print_exc()

        print(f"  Próximo ciclo en {NOTIFY_INTERVAL}s...")
        time.sleep(NOTIFY_INTERVAL)


if __name__ == '__main__':
    if not TELEGRAM_BOT_TOKEN and not DRY_RUN:
        print("⚠️  TELEGRAM_BOT_TOKEN no configurado. Usa DRY_RUN=true para probar.")
    run()
