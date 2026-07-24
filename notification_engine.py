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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

SMTP_HOST             = os.getenv('SMTP_HOST', '')
SMTP_PORT             = int(os.getenv('SMTP_PORT', 587))
SMTP_USER             = os.getenv('SMTP_USER', '')
SMTP_PASS             = os.getenv('SMTP_PASS', '')
FROM_EMAIL            = os.getenv('FROM_EMAIL', '')
TO_EMAILS             = [e.strip() for e in os.getenv('TO_EMAILS', '').split(',') if e.strip()]
SMTP_USE_TLS          = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'

CLIENT_ID             = os.getenv('ACRONIS_CLIENT_ID', '')
CLIENT_SECRET         = os.getenv('ACRONIS_CLIENT_SECRET', '')
DC_URL                = os.getenv('ACRONIS_DC_URL', 'https://us5-cloud.acronis.com').rstrip('/')

NOTIFY_INTERVAL       = int(os.getenv('NOTIFY_INTERVAL_SECONDS', 300))
REMIND_INTERVAL_H     = int(os.getenv('REMIND_INTERVAL_H', 6))
BACKUP_WARN_H         = int(os.getenv('NOTIFY_BACKUP_HOURS', 25))
BACKUP_CRIT_H         = int(os.getenv('NOTIFY_BACKUP_CRIT_HOURS', 48))
CYBERFIT_THR          = int(os.getenv('CYBERFIT_THRESHOLD', 500))
ACRONIS_ALERTS_ON     = os.getenv('ACRONIS_ALERTS_ENABLED', 'true').lower() == 'true'
NOTIFY_BACKUP_SUCCESS = os.getenv('NOTIFY_BACKUP_SUCCESS', 'true').lower() == 'true'
DRY_RUN               = os.getenv('DRY_RUN', 'false').lower() == 'true'

# ─────────────────────────── Tipos de alerta ───────────────────────────────

class AlertType:
    BACKUP_NO_RECORD   = 'BACKUP_NO_RECORD'    # nunca hizo backup
    BACKUP_WARN        = 'BACKUP_OVERDUE_25H'  # >25h sin backup
    BACKUP_CRIT        = 'BACKUP_OVERDUE_48H'  # >48h sin backup
    BACKUP_SUCCESS     = 'BACKUP_SUCCESS'      # backup exitoso registrado
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


# ─────────────────────────── Email SMTP ────────────────────────────────────

def send_email(subject: str, html_body: str, force_cfg: dict = None) -> bool:
    """Envía correo a todos los destinatarios configurados en DB o .env."""
    if DRY_RUN:
        print(f"[DRY_RUN] Email Subject: {subject}\n[DRY_RUN] Email Body Preview:\n{html_body[:200]}...\n")
        return True

    cfg = force_cfg or db.get_channel_config('email')

    host      = cfg.get('smtp_host') or SMTP_HOST
    port      = int(cfg.get('smtp_port') or SMTP_PORT or 587)
    user      = cfg.get('smtp_user') or SMTP_USER
    pwd       = cfg.get('smtp_pass') or SMTP_PASS
    from_addr = cfg.get('from_email') or FROM_EMAIL or user
    to_addrs  = cfg.get('to_emails') or TO_EMAILS
    use_tls   = cfg.get('use_tls') if cfg.get('use_tls') is not None else SMTP_USE_TLS
    enabled   = cfg.get('enabled')

    if enabled is None:
        enabled = bool(host and to_addrs)

    if not enabled:
        return False

    if not host or not to_addrs:
        print("[WARN] Email habilitado pero no configurado (SMTP Host/Destinatarios vacíos)")
        return False

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = from_addr
        msg['To']      = ', '.join(to_addrs)
        msg.attach(MIMEText(html_body, 'html'))

        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=15) as srv:
                if user and pwd:
                    srv.login(user, pwd)
                srv.sendmail(from_addr, to_addrs, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as srv:
                if use_tls:
                    srv.starttls()
                if user and pwd:
                    srv.login(user, pwd)
                srv.sendmail(from_addr, to_addrs, msg.as_string())
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False


def dispatch_notifications(vm_notify: bool, msg_tg: str, subj_em: str, html_em: str) -> bool:
    """Envía notificaciones a través de todos los canales activos (Telegram, Email)."""
    if not vm_notify:
        return False

    tg_sent = send_telegram(msg_tg)
    em_sent = send_email(subj_em, html_em)
    return tg_sent or em_sent


def now_chile() -> datetime:
    """Retorna la hora actual en Chile (UTC-4)."""
    return datetime.now(timezone(timedelta(hours=-4)))


def fmt_ts(iso: Optional[str]) -> str:
    if not iso:
        return "Nunca"
    try:
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


def msg_backup_success(vm: dict) -> str:
    size_gb  = vm.get('backup_size_gb', 0)
    size_str = f" ({size_gb:.1f} GB)" if size_gb else ""
    return (
        f"✅ <b>RESPALDO EXITOSO</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥️  <b>{vm['name']}</b>\n"
        f"🏢 {vm.get('tenant_name','')}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📅 Fecha de respaldo: <b>{fmt_ts(vm.get('last_backup_success'))}</b>\n"
        f"📋 Plan: {vm.get('protection_plan','N/A')}\n"
        f"💾 Tamaño: {size_str or 'N/A'}\n"
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


# ─────────────────────────── Plantillas Email HTML ─────────────────────────

def render_email_html(title: str, badge_text: str, badge_color: str, rows_html: str) -> str:
    ts_now = now_chile().strftime('%d/%m/%Y %H:%M')
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#f1f5f9;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#0f172a;padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:560px;background-color:#1e293b;border-radius:12px;border:1px solid #334155;overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.5);">
          <!-- Header -->
          <tr>
            <td style="padding:20px 24px;background-color:#0f172a;border-bottom:1px solid #334155;">
              <table width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <span style="font-size:18px;font-weight:bold;color:#38bdf8;">🛡️ Acronis VM Monitor</span>
                  </td>
                  <td align="right">
                    <span style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:bold;color:#ffffff;background-color:{badge_color};letter-spacing:0.5px;">
                      {badge_text}
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:24px;">
              <h2 style="margin:0 0 18px 0;font-size:20px;font-weight:700;color:#f8fafc;">{title}</h2>
              <table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;">
                {rows_html}
              </table>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding:16px 24px;background-color:#0f172a;border-top:1px solid #334155;font-size:12px;color:#94a3b8;text-align:center;">
              Monitoreo de Infraestructura Acronis &bull; {ts_now} (Chile)
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _email_row(label: str, val: str, is_highlight: bool = False) -> str:
    val_style = "font-weight:bold;color:#f8fafc;" if is_highlight else "color:#cbd5e1;"
    return f"""
    <tr>
      <td style="padding:8px 0;border-bottom:1px solid #334155;font-size:14px;color:#94a3b8;width:35%;">{label}</td>
      <td style="padding:8px 0;border-bottom:1px solid #334155;font-size:14px;{val_style}">{val}</td>
    </tr>"""


def msg_email_backup_warn(vm: dict, hours: float, escalated: bool = False) -> Tuple[str, str]:
    is_crit     = hours >= BACKUP_CRIT_H
    badge_text  = "CRÍTICO" if is_crit else "ADVERTENCIA"
    badge_color = "#ef4444" if is_crit else "#f59e0b"
    title       = f"⚠️ ESCALADO: Backup atrasado" if escalated else f"Alerta de Backup ({badge_text})"
    subj        = f"{'🔴' if is_crit else '🟡'} [{badge_text}] Backup atrasado ({hours:.0f}h) – {vm['name']}"

    rows = (
        _email_row("Equipo / VM", vm['name'], True) +
        _email_row("Cliente / Tenant", vm.get('tenant_name', 'N/A')) +
        _email_row("Tiempo sin backup", f"<span style='color:{badge_color};font-weight:bold;'>{hours:.0f} horas</span>") +
        _email_row("Último backup", fmt_ts(vm.get('last_backup_success'))) +
        _email_row("Plan de Protección", vm.get('protection_plan', 'N/A')) +
        _email_row("Estado Protección", (vm.get('protection_status') or 'unknown').upper())
    )
    return subj, render_email_html(title, badge_text, badge_color, rows)


def msg_email_backup_success(vm: dict) -> Tuple[str, str]:
    subj = f"✅ [EXITOSO] Respaldo completado – {vm['name']}"
    size_gb  = vm.get('backup_size_gb', 0)
    size_str = f"{size_gb:.1f} GB" if size_gb else "N/A"
    rows = (
        _email_row("Equipo / VM", vm['name'], True) +
        _email_row("Cliente / Tenant", vm.get('tenant_name', 'N/A')) +
        _email_row("Fecha de Respaldo", fmt_ts(vm.get('last_backup_success'))) +
        _email_row("Plan de Protección", vm.get('protection_plan', 'N/A')) +
        _email_row("Tamaño de Backup", size_str)
    )
    return subj, render_email_html("Respaldo Completado Exitosamente", "EXITOSO", "#10b981", rows)


def msg_email_backup_no_record(vm: dict) -> Tuple[str, str]:
    subj = f"⚫ [ALERTA] Sin registro de backup – {vm['name']}"
    rows = (
        _email_row("Equipo / VM", vm['name'], True) +
        _email_row("Cliente / Tenant", vm.get('tenant_name', 'N/A')) +
        _email_row("Detalle", "<span style='color:#ef4444;font-weight:bold;'>Sin registros de backup exitoso</span>") +
        _email_row("Plan de Protección", vm.get('protection_plan', 'Sin Plan'))
    )
    return subj, render_email_html("Equipo Sin Registro de Backup", "SIN BACKUP", "#64748b", rows)


def msg_email_cyberfit(vm: dict) -> Tuple[str, str]:
    score = vm.get('cyberfit_score', 0)
    subj  = f"🛡️ [ADVERTENCIA] CyberFit Score Bajo ({score}/850) – {vm['name']}"
    rows  = (
        _email_row("Equipo / VM", vm['name'], True) +
        _email_row("Cliente / Tenant", vm.get('tenant_name', 'N/A')) +
        _email_row("CyberFit Score", f"<span style='color:#f59e0b;font-weight:bold;'>{score} / 850</span>") +
        _email_row("Umbral Mínimo", str(CYBERFIT_THR))
    )
    return subj, render_email_html("CyberFit Score Bajo Umbral", "CYBERFIT", "#f59e0b", rows)


def msg_email_status(vm: dict) -> Tuple[str, str]:
    st          = (vm.get('protection_status') or '').upper()
    is_crit     = st == 'CRITICAL'
    badge_color = "#ef4444" if is_crit else "#f59e0b"
    subj        = f"{'🔴' if is_crit else '🟡'} [{st}] Estado de Protección – {vm['name']}"
    rows        = (
        _email_row("Equipo / VM", vm['name'], True) +
        _email_row("Cliente / Tenant", vm.get('tenant_name', 'N/A')) +
        _email_row("Estado Protección", f"<span style='color:{badge_color};font-weight:bold;'>{st}</span>") +
        _email_row("Plan de Protección", vm.get('protection_plan', 'N/A')) +
        _email_row("Último Backup", fmt_ts(vm.get('last_backup_success')))
    )
    return subj, render_email_html(f"Estado de Protección {st}", st, badge_color, rows)


def msg_email_resolved(vm_name: str, tenant: str, alert_type: str, first_sent: str) -> Tuple[str, str]:
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
    subj  = f"✅ [RESUELTO] {label} – {vm_name}"
    rows  = (
        _email_row("Equipo / VM", vm_name, True) +
        _email_row("Cliente / Tenant", tenant) +
        _email_row("Alerta Resuelta", label) +
        _email_row("Activa Desde", fmt_ts(first_sent))
    )
    return subj, render_email_html("Alerta Resuelta Exitosamente", "RESUELTO", "#10b981", rows)


def msg_email_acronis_alert(alert: dict) -> Tuple[str, str]:
    sev         = alert.get('severity', 'info').upper()
    is_crit     = sev in ('CRITICAL', 'HIGH')
    badge_color = "#ef4444" if is_crit else "#f59e0b"
    atype       = alert.get('type', 'N/A')
    rname       = alert.get('details', {}).get('resource_name') or 'N/A'
    tname       = alert.get('details', {}).get('tenant_name')   or 'N/A'
    desc        = alert.get('details', {}).get('description')   or atype
    subj        = f"{'🔴' if is_crit else '🟡'} [ACRONIS {sev}] {atype} – {rname}"

    rows = (
        _email_row("Recurso", rname, True) +
        _email_row("Cliente / Tenant", tname) +
        _email_row("Tipo Alerta", f"<code>{atype}</code>") +
        _email_row("Severidad", f"<span style='color:{badge_color};font-weight:bold;'>{sev}</span>") +
        _email_row("Descripción", desc)
    )
    return subj, render_email_html(f"Alerta Nativa Acronis ({sev})", sev, badge_color, rows)


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
    Envía notificaciones multicanal (Telegram, Email) según configuración.
    """
    sent = 0

    for vm in machines:
        vm_id   = vm.get('vm_id')
        vm_name = vm.get('name', vm_id)
        tenant  = vm.get('tenant_name', '')
        notify  = bool(vm.get('notify_telegram')) # Preferencia de notificación

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
                sub_em, html_em = msg_email_backup_no_record(vm)
                dispatch_notifications(notify, msg_backup_no_record(vm), sub_em, html_em)
                sent += 1
        else:
            if db.resolve_notification(vm_id, AlertType.BACKUP_NO_RECORD, now_iso):
                sub_em, html_em = msg_email_resolved(vm_name, tenant, AlertType.BACKUP_NO_RECORD, now_iso)
                dispatch_notifications(notify, msg_resolved(vm_name, tenant, AlertType.BACKUP_NO_RECORD, now_iso), sub_em, html_em)

        # ── 2. Backup atrasado ──────────────────────────────────────────────
        hours = hours_since(vm.get('last_backup_success'))
        if hours is not None:
            if hours >= BACKUP_CRIT_H:
                snd, esc = should_send(vm_id, AlertType.BACKUP_CRIT, 'critical', now_iso)
                if snd:
                    db.upsert_notification(vm_id, vm_name, tenant,
                                           AlertType.BACKUP_CRIT, 'critical', now_iso,
                                           extra_data={'hours': round(hours, 1)})
                    sub_em, html_em = msg_email_backup_warn(vm, hours, escalated=esc)
                    dispatch_notifications(notify, msg_backup_warn(vm, hours, escalated=esc), sub_em, html_em)
                    sent += 1
                db.resolve_notification(vm_id, AlertType.BACKUP_WARN, now_iso)

            elif hours >= BACKUP_WARN_H:
                snd, esc = should_send(vm_id, AlertType.BACKUP_WARN, 'warning', now_iso)
                if snd:
                    db.upsert_notification(vm_id, vm_name, tenant,
                                           AlertType.BACKUP_WARN, 'warning', now_iso,
                                           extra_data={'hours': round(hours, 1)})
                    sub_em, html_em = msg_email_backup_warn(vm, hours)
                    dispatch_notifications(notify, msg_backup_warn(vm, hours), sub_em, html_em)
                    sent += 1
            else:
                for atype in (AlertType.BACKUP_WARN, AlertType.BACKUP_CRIT):
                    existing = db.get_active_notification(vm_id, atype)
                    if existing and db.resolve_notification(vm_id, atype, now_iso):
                        sub_em, html_em = msg_email_resolved(vm_name, tenant, atype, existing['first_sent'])
                        dispatch_notifications(notify, msg_resolved(vm_name, tenant, atype, existing['first_sent']), sub_em, html_em)
                        sent += 1

        # ── 3. CyberFit bajo ───────────────────────────────────────────────
        score = int(vm.get('cyberfit_score') or 0)
        if score > 0 and score < CYBERFIT_THR:
            snd, _ = should_send(vm_id, AlertType.CYBERFIT_LOW, 'warning', now_iso)
            if snd:
                db.upsert_notification(vm_id, vm_name, tenant,
                                       AlertType.CYBERFIT_LOW, 'warning', now_iso,
                                       extra_data={'score': score})
                sub_em, html_em = msg_email_cyberfit(vm)
                dispatch_notifications(notify, msg_cyberfit(vm), sub_em, html_em)
                sent += 1
        elif score >= CYBERFIT_THR:
            existing = db.get_active_notification(vm_id, AlertType.CYBERFIT_LOW)
            if existing and db.resolve_notification(vm_id, AlertType.CYBERFIT_LOW, now_iso):
                sub_em, html_em = msg_email_resolved(vm_name, tenant, AlertType.CYBERFIT_LOW, existing['first_sent'])
                dispatch_notifications(notify, msg_resolved(vm_name, tenant, AlertType.CYBERFIT_LOW, existing['first_sent']), sub_em, html_em)
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
                    sub_em, html_em = msg_email_status(vm)
                    dispatch_notifications(notify, msg_status(vm), sub_em, html_em)
                    sent += 1
            else:
                existing = db.get_active_notification(vm_id, at)
                if existing and db.resolve_notification(vm_id, at, now_iso):
                    sub_em, html_em = msg_email_resolved(vm_name, tenant, at, existing['first_sent'])
                    dispatch_notifications(notify, msg_resolved(vm_name, tenant, at, existing['first_sent']), sub_em, html_em)
                    sent += 1

        # ── 5. Respaldo exitoso ──────────────────────────────────────────────
        if NOTIFY_BACKUP_SUCCESS and has_backup:
            last_success  = vm.get('last_backup_success')
            last_notified = vm.get('last_backup_success_notified')

            if last_success and last_success != last_notified:
                sub_em, html_em = msg_email_backup_success(vm)
                if dispatch_notifications(notify, msg_backup_success(vm), sub_em, html_em):
                    db.set_backup_success_notified(vm_id, last_success)
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
    Consulta las alertas nativas de Acronis y notifica por Telegram y Email.
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

            alert_id  = alert.get('id', atype)
            sev_raw   = (alert.get('severity') or 'warning').lower()
            sev       = 'critical' if sev_raw in ('critical','high') else 'warning'

            resource_id = (alert.get('details', {}).get('resource_id')
                           or alert.get('details', {}).get('context_id')
                           or alert_id)
            notif_key   = f"ACRONIS_{atype}_{resource_id}"

            snd, _ = should_send(resource_id, notif_key, sev, now_iso)
            if snd:
                msg_tg = msg_acronis_alert(alert)
                sub_em, html_em = msg_email_acronis_alert(alert)
                tg_ok = send_telegram(msg_tg)
                em_ok = send_email(sub_em, html_em)

                if tg_ok or em_ok:
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

    email_cfg = db.get_channel_config('email')
    email_active = bool(email_cfg.get('enabled') or (SMTP_HOST and TO_EMAILS))

    print(f"\n{'='*60}")
    print(f"  Acronis Notification Engine")
    print(f"  Intervalo      : {NOTIFY_INTERVAL}s")
    print(f"  Re-notificación: cada {REMIND_INTERVAL_H}h")
    print(f"  Backup warning : >{BACKUP_WARN_H}h  |  critical: >{BACKUP_CRIT_H}h")
    print(f"  CyberFit mín   : {CYBERFIT_THR}")
    print(f"  Telegram       : {'✅ configurado' if (TELEGRAM_BOT_TOKEN or db.get_channel_config('telegram').get('enabled')) else '❌ NO configurado'}")
    print(f"  Email SMTP     : {'✅ configurado' if email_active else '❌ NO configurado'}")
    print(f"  Backup Exitoso : {'✅ activo' if NOTIFY_BACKUP_SUCCESS else '❌ desactivado'}")
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
    if not TELEGRAM_BOT_TOKEN and not DRY_RUN and not (SMTP_HOST and TO_EMAILS):
        print("⚠️  Ni TELEGRAM_BOT_TOKEN ni SMTP están configurados. Usa DRY_RUN=true para probar.")
    run()
