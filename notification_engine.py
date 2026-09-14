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
import re
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


# ─────────────────────── Módulo de Reportes Ejecutivos ──────────────────────

def format_bytes_human(num_bytes: int) -> str:
    """Convierte bytes a formato legible (B, KB, MB, GB, TB)."""
    if not num_bytes or num_bytes <= 0:
        return "0 GB"
    val = float(num_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if abs(val) < 1024.0:
            return f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} PB"


def format_duration_human(seconds: int) -> str:
    """Convierte segundos a formato amigable (ej: 45s, 14m, 1h 20m)."""
    if not seconds or seconds <= 0:
        return "< 1 min"
    sec = int(seconds)
    if sec < 60:
        return f"{sec}s"
    m = sec // 60
    rem_s = sec % 60
    if m < 60:
        return f"{m}m {rem_s}s" if rem_s > 0 else f"{m}m"
    h = m // 60
    rem_m = m % 60
    return f"{h}h {rem_m}m"


def find_best_tenant_storage(t_name: str, stor_list: list) -> dict:
    """Encuentra el mejor registro de almacenamiento para un tenant, resolviendo si una unidad
    hija reporta 0 bytes locales mientras el cliente padre concentra los bytes reales de NTFS."""
    if not t_name or not stor_list:
        return None
    t_clean = re.sub(r'[^a-z0-9]', '', t_name.lower())
    candidates = []
    for ts in stor_list:
        ts_name = ts.get('tenant_name', '')
        ts_clean = re.sub(r'[^a-z0-9]', '', ts_name.lower())
        if ts_name.lower().strip() == t_name.lower().strip() or ts_clean == t_clean:
            candidates.append(ts)
        elif len(t_clean) >= 4 and (t_clean in ts_clean or ts_clean in t_clean):
            candidates.append(ts)
        elif 'integra' in t_clean and 'integra' in ts_clean:
            candidates.append(ts)

    if not candidates:
        return None

    # Si hay registros con almacenamiento local reportado (>0), preferir el nivel customer o mayor local_bytes
    with_local = [c for c in candidates if c.get('local_bytes', 0) > 0]
    if with_local:
        with_local.sort(key=lambda x: (x.get('kind') == 'customer', x.get('local_bytes', 0)), reverse=True)
        return with_local[0]

    candidates.sort(key=lambda x: x.get('total_bytes', 0), reverse=True)
    return candidates[0]


def generate_weekly_report_data(start_iso: str = None, end_iso: str = None, tenant_id: str = None, vm_ids: list = None) -> dict:
    """
    Genera el diccionario de datos consolidados para el reporte ejecutivo.
    Soporta filtrado exclusivo por máquinas seleccionadas (vm_ids).
    """
    now = datetime.now(timezone.utc)
    if not end_iso:
        end_iso = now.isoformat()
    if not start_iso:
        start_iso = (now - timedelta(days=7)).isoformat()

    cfg = db.get_report_config()
    # Si no se pasan vm_ids explícitos, verificar si hay máquinas preconfiguradas
    if vm_ids is None:
        saved_vms = cfg.get('selected_vm_ids', [])
        if saved_vms:
            vm_ids = saved_vms

    metrics = db.get_backup_metrics(start_iso, end_iso, tenant_id, vm_ids=vm_ids)
    storage_list = db.get_latest_storage_metrics()
    machines = metrics.get('machines', [])

    # Cargar almacenamiento por tenant para enriquecer máquinas y clientes
    tenant_storages = db.get_all_tenant_storages()
    stor_by_name = {}
    for ts in tenant_storages:
        raw_n = ts['tenant_name']
        stor_by_name[raw_n.lower().strip()] = ts
        clean_k = re.sub(r'[^a-z0-9]', '', raw_n.lower())
        if clean_k:
            stor_by_name[clean_k] = ts
        if ts.get('tenant_id'):
            stor_by_name[str(ts['tenant_id']).strip()] = ts

    # 1. Rendimiento y Volumen (Punto 1)
    total_volume_str = format_bytes_human(metrics.get('total_size_bytes', 0))
    avg_duration_str = format_duration_human(metrics.get('avg_duration_seconds', 0))
    total_duration_str = format_duration_human(metrics.get('total_duration_seconds', 0))

    # 2. Desglose y Clasificación de Riesgo (Punto 3)
    no_history = []
    overdue_24h = []
    overdue_48h = []
    no_plan = []
    low_cyberfit = []

    servers_detail = []
    tenants_map = {}

    for m in machines:
        vm_name = m.get('name') or m.get('vm_id')
        tenant = m.get('tenant_name', 'N/A')
        plan = m.get('protection_plan') or 'Sin Plan'
        last_succ = m.get('last_backup_success')
        hs = hours_since(last_succ)
        score = int(m.get('cyberfit_score') or 0)
        p_status = (m.get('protection_status') or 'unknown').upper()
        if p_status == 'OK' and hs is not None and hs >= 25:
            p_status = 'WARNING'

        # Evaluación de riesgos
        if not last_succ:
            no_history.append({'name': vm_name, 'tenant': tenant, 'reason': 'Sin respaldo histórico registrado'})
        elif hs is not None:
            if hs >= 48:
                overdue_48h.append({'name': vm_name, 'tenant': tenant, 'hours': int(hs), 'reason': f'Sin respaldo hace {int(hs)}h (>48h)'})
            elif hs >= 25:
                overdue_24h.append({'name': vm_name, 'tenant': tenant, 'hours': int(hs), 'reason': f'Sin respaldo hace {int(hs)}h (>24h)'})

        if not m.get('protection_plan') or m.get('protection_plan') in ('Sin Plan', 'No plan'):
            no_plan.append({'name': vm_name, 'tenant': tenant, 'reason': 'Sin plan de protección asignado'})

        if score > 0 and score < CYBERFIT_THR:
            low_cyberfit.append({'name': vm_name, 'tenant': tenant, 'score': score, 'reason': f'CyberFit Score bajo ({score}/{CYBERFIT_THR})'})

        # Estado de antigüedad
        if hs is not None:
            if hs < 24:
                age_str = f"Hace {int(hs)}h"
                age_status = "ok"
            elif hs < 48:
                age_str = f"Hace {int(hs)}h ⚠️"
                age_status = "warn"
            else:
                age_str = f"Hace {int(hs // 24)}d {int(hs % 24)}h 🔴"
                age_status = "crit"
        else:
            age_str = "Sin registro histórico"
            age_status = "crit"

        # Duración formateada
        dur_sec = m.get('latest_duration_seconds', 0)
        dur_str = format_duration_human(dur_sec) if dur_sec > 0 else "< 1 min"

        # Tamaño Local (NTFS) vs Cloud
        loc_b = m.get('latest_local_bytes', 0)
        cld_b = m.get('latest_cloud_bytes', 0)
        plan_str = plan.lower()

        has_local_plan = any(k in plan_str for k in ('[local]', 'local', 'ntfs', 'smb', 'disco local', 'carpeta local'))
        has_cloud_plan = any(k in plan_str for k in ('cloud', 'acronis')) or (';' in plan_str and has_local_plan) or (not has_local_plan)

        # Identificar si es una carga de base de datos o sub-recurso (ej. SQL Server)
        is_db_workload = '://' in vm_name.lower() or 'mssql' in vm_name.lower()

        # Si el plan explícitamente incluye respaldo local y loc_b es 0, usar el tamaño de respaldo de la máquina
        raw_sz = m.get('latest_size_bytes', 0) or int((m.get('backup_size_gb') or 0) * (1024**3))

        # Si no tiene ejecuciones ni último backup exitoso, no tiene datos almacenados
        if not last_succ and m.get('backup_count', 0) == 0:
            loc_b = 0
            cld_b = 0
        else:
            if has_local_plan and loc_b == 0 and raw_sz > 0:
                loc_b = raw_sz
            if has_cloud_plan and cld_b == 0 and raw_sz > 0:
                cld_b = raw_sz

        ts_match = find_best_tenant_storage(tenant, tenant_storages)

        # Solo prorratear almacenamiento de tenant para máquinas/servidores reales con respaldo activo,
        # NUNCA para bases de datos individuales ni para equipos sin respaldos
        if not is_db_workload and loc_b == 0 and cld_b == 0 and ts_match and (last_succ or m.get('backup_count', 0) > 0):
            non_db_machines = [x for x in machines if x.get('tenant_name') == tenant and not ('://' in (x.get('name') or '').lower() or 'mssql' in (x.get('name') or '').lower())]
            tot_vms_in_t = max(1, len(non_db_machines))
            if ts_match.get('local_bytes', 0) > 0 and ts_match.get('cloud_bytes', 0) == 0:
                loc_b = int(ts_match['local_bytes'] / tot_vms_in_t)
            elif ts_match.get('cloud_bytes', 0) > 0 and ts_match.get('local_bytes', 0) == 0:
                cld_b = int((ts_match.get('vm_bytes') or ts_match['cloud_bytes']) / tot_vms_in_t)
            elif ts_match.get('local_bytes', 0) > 0 and ts_match.get('cloud_bytes', 0) > 0:
                loc_b = int(ts_match['local_bytes'] / tot_vms_in_t)
                cld_b = int(ts_match['cloud_bytes'] / tot_vms_in_t)

        size_tot = loc_b + cld_b

        # Próximo backup
        next_b = m.get('next_backup')
        next_b_str = fmt_ts(next_b) if next_b else "No programado"

        # Velocidad y métricas de procesamiento de la última actividad
        speed_bps = m.get('latest_speed_bps', 0.0) or 0.0
        if speed_bps <= 0 and dur_sec > 0 and (m.get('latest_bytes_processed') or raw_sz) > 0:
            speed_bps = (m.get('latest_bytes_processed') or raw_sz) / max(1, dur_sec)
        speed_mb_s = round(speed_bps / (1024**2), 2)
        speed_str = f"{speed_mb_s} MB/s" if speed_mb_s > 0 else "< 0.1 MB/s"

        b_proc = m.get('latest_bytes_processed', 0) or raw_sz
        b_proc_str = format_bytes_human(b_proc) if b_proc > 0 else "0 GB"
        b_saved = m.get('latest_bytes_saved', 0) or raw_sz
        b_saved_str = format_bytes_human(b_saved) if b_saved > 0 else "0 GB"

        servers_detail.append({
            'vm_id': m.get('vm_id'),
            'name': vm_name,
            'tenant_name': tenant,
            'plan_name': plan,
            'backup_count': m.get('backup_count', 0),
            'backup_count_str': m.get('backup_count_str', '0'),
            'last_backup_formatted': fmt_ts(last_succ),
            'next_backup_formatted': next_b_str,
            'age_str': age_str,
            'age_status': age_status,
            'duration_str': dur_str,
            'duration_seconds': dur_sec,
            'speed_str': speed_str,
            'bytes_processed_str': b_proc_str,
            'bytes_saved_str': b_saved_str,
            'bottleneck_label': m.get('latest_bottleneck_label') or 'Escribir datos en el destino',
            'latest_activity_id': m.get('latest_activity_id'),
            'latest_task_id': m.get('latest_task_id'),
            'size_local_bytes': loc_b,
            'size_cloud_bytes': cld_b,
            'size_local_str': format_bytes_human(loc_b) if loc_b > 0 else "0 GB",
            'size_cloud_str': format_bytes_human(cld_b) if cld_b > 0 else "0 GB",
            'size_str': format_bytes_human(size_tot) if size_tot > 0 else "0 GB",
            'agent_version': m.get('agent_version') or 'Desconocido',
            'cyberfit': score,
            'status': p_status,
            'latest_result': m.get('latest_result', 'success'),
            'latest_error': m.get('latest_error')
        })

        # Agrupación por Tenant (Punto 4)
        if tenant not in tenants_map:
            tenants_map[tenant] = {
                'tenant_name': tenant,
                'total_vms': 0,
                'ok_count': 0,
                'warn_count': 0,
                'crit_count': 0,
                'total_bytes': 0,
            }
        tenants_map[tenant]['total_vms'] += 1
        tenants_map[tenant]['total_bytes'] += size_tot
        if p_status == 'OK':
            tenants_map[tenant]['ok_count'] += 1
        elif p_status == 'WARNING':
            tenants_map[tenant]['warn_count'] += 1
        else:
            tenants_map[tenant]['crit_count'] += 1

    # Formatear resumen por Tenant con datos de almacenamiento y cuotas
    for ts in tenant_storages:
        raw_n = ts['tenant_name']
        stor_by_name[raw_n.lower().strip()] = ts
        clean_k = re.sub(r'[^a-z0-9]', '', raw_n.lower())
        if clean_k:
            stor_by_name[clean_k] = ts
        if ts.get('tenant_id'):
            stor_by_name[str(ts['tenant_id']).strip()] = ts

    tenants_summary = []
    for t_data in tenants_map.values():
        tot = t_data['total_vms']
        ok_c = t_data['ok_count']
        t_rate = round((ok_c / tot * 100.0), 1) if tot > 0 else 100.0
        t_name = t_data['tenant_name']
        t_clean = re.sub(r'[^a-z0-9]', '', t_name.lower())

        # Buscar coincidencia en tenant_storage priorizando resolución de niveles con almacenamiento local
        ts_match = find_best_tenant_storage(t_name, tenant_storages)

        tot_bytes = ts_match['total_bytes'] if ts_match and ts_match.get('total_bytes') else t_data['total_bytes']
        loc_bytes = ts_match.get('local_bytes', 0) if ts_match else 0
        cld_bytes = ts_match.get('cloud_bytes', 0) if ts_match else max(0, tot_bytes - loc_bytes)
        q_bytes = ts_match.get('quota_bytes') if ts_match else None
        q_pct = ts_match.get('usage_percent', 0.0) if ts_match else 0.0

        tenants_summary.append({
            'tenant_name': t_name,
            'total_vms': tot,
            'success_rate': t_rate,
            'ok_count': ok_c,
            'issues_count': t_data['warn_count'] + t_data['crit_count'],
            'total_volume_str': format_bytes_human(tot_bytes),
            'local_storage_str': format_bytes_human(loc_bytes),
            'cloud_storage_str': format_bytes_human(cld_bytes),
            'quota_str': format_bytes_human(q_bytes) if q_bytes else "Flexible",
            'usage_percent': q_pct,
            'status': 'OK' if t_rate >= 90 else ('WARNING' if t_rate >= 70 else 'CRITICAL')
        })
    tenants_summary.sort(key=lambda x: x['tenant_name'])

    # Procesar almacenamiento
    storages_processed = []
    local_warn_pct = cfg.get('local_warn_pct', 85)
    cloud_warn_pct = cfg.get('cloud_warn_pct', 90)

    for st in storage_list:
        st_type = st.get('storage_type', 'local_ntfs')
        pct = st.get('usage_percent', 0.0)
        thr = local_warn_pct if st_type == 'local_ntfs' else cloud_warn_pct
        is_warning = pct >= thr

        storages_processed.append({
            'name': st.get('storage_name'),
            'type': st_type,
            'type_label': 'Almacenamiento Local (NTFS)' if st_type == 'local_ntfs' else 'Almacenamiento Cloud (Acronis)',
            'tenant_name': st.get('tenant_name'),
            'total_str': format_bytes_human(st.get('total_bytes', 0)),
            'used_str': format_bytes_human(st.get('used_bytes', 0)),
            'free_str': format_bytes_human(st.get('free_bytes', 0)),
            'usage_percent': pct,
            'is_warning': is_warning,
            'threshold': thr,
            'timestamp': fmt_ts(st.get('timestamp'))
        })

    return {
        'period_start': fmt_ts(start_iso),
        'period_end': fmt_ts(end_iso),
        'generated_at': now_chile().strftime('%d/%m/%Y %H:%M'),
        'total_machines': len(machines),
        'is_filtered_selection': bool(vm_ids and len(vm_ids) > 0),
        'total_executions': metrics.get('total_executions', 0),
        'success_count': metrics.get('success_count', 0),
        'warning_count': metrics.get('warning_count', 0),
        'failed_count': metrics.get('failed_count', 0),
        'success_rate': metrics.get('success_rate', 100.0),
        'total_volume_str': total_volume_str,
        'avg_duration_str': avg_duration_str,
        'total_duration_str': total_duration_str,
        'plans_distribution': metrics.get('plans_distribution', {}),
        'affected_machines': metrics.get('affected_machines', []),
        'risk_summary': {
            'no_history': no_history,
            'overdue_48h': overdue_48h,
            'overdue_24h': overdue_24h,
            'no_plan': no_plan,
            'low_cyberfit': low_cyberfit,
            'total_risks': len(no_history) + len(overdue_48h) + len(overdue_24h) + len(no_plan)
        },
        'tenants_summary': tenants_summary,
        'servers_detail': servers_detail,
        'storages': storages_processed
    }


def get_backupcode_logo_base64() -> str:
    """Retorna el logo de Backupcode codificado en base64 para embeber en HTML/PDF."""
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backupcode_logo.png')
    if os.path.exists(logo_path):
        try:
            with open(logo_path, 'rb') as f:
                return "data:image/png;base64," + b64encode(f.read()).decode('utf-8')
        except Exception:
            return ""
    return ""


def render_report_html(data: dict, for_pdf: bool = False) -> str:
    """Genera la plantilla HTML ejecutiva completa con puntos 1, 2, 3 y 4 con branding de Backupcode."""
    rate = data.get('success_rate', 100.0)
    rate_color = "#10b981" if rate >= 95 else ("#f59e0b" if rate >= 80 else "#ef4444")
    logo_b64 = get_backupcode_logo_base64()

    # Scope badge
    is_filt = data.get('is_filtered_selection')
    scope_badge = f"""<span style="display:inline-block;padding:4px 10px;background:#3b82f622;color:#60a5fa;border:1px solid #3b82f655;border-radius:6px;font-size:12px;font-weight:600;margin-top:4px;">
      🎯 Alcance: {data.get('total_machines',0)} máquinas seleccionadas
    </span>""" if is_filt else f"""<span style="display:inline-block;padding:4px 10px;background:#1e293b;color:#94a3b8;border:1px solid #334155;border-radius:6px;font-size:12px;font-weight:600;margin-top:4px;">
      🌐 Alcance: Todos los equipos visibles ({data.get('total_machines',0)})
    </span>"""

    # Logo HTML
    logo_html = f"""<td width="75" style="vertical-align:middle;padding-right:16px;">
      <img src="{logo_b64}" width="65" style="width:65px;display:block;" alt="Backupcode" />
    </td>""" if logo_b64 else ""

    # CSS específico para PDF
    pdf_style = """
    @page {
      size: a4 portrait;
      margin: 8mm;
    }
    table {
      page-break-inside: auto;
    }
    tr {
      page-break-inside: avoid;
      page-break-after: auto;
    }
    thead {
      display: table-header-group;
    }
    """ if for_pdf else ""

    # 1. KPIs de Rendimiento y Volumen (Punto 1)
    kpis_html = f"""
    <table width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:24px;">
      <tr>
        <td width="16%" style="padding:4px;">
          <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:800;color:#ffffff;">{data.get('total_machines',0)}</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Equipos Evaluados</div>
          </div>
        </td>
        <td width="16%" style="padding:4px;">
          <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:800;color:{rate_color};">{data.get('success_rate',100.0)}%</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Tasa de Éxito</div>
          </div>
        </td>
        <td width="20%" style="padding:4px;">
          <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:20px;font-weight:800;color:#38bdf8;">{data.get('total_volume_str','0 GB')}</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Volumen Total Procesado</div>
          </div>
        </td>
        <td width="16%" style="padding:4px;">
          <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:20px;font-weight:800;color:#a78bfa;">{data.get('avg_duration_str','< 1m')}</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Duración Promedio</div>
          </div>
        </td>
        <td width="16%" style="padding:4px;">
          <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:20px;font-weight:800;color:#10b981;">{data.get('success_count',0)}</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Respaldos Exitosos</div>
          </div>
        </td>
        <td width="16%" style="padding:4px;">
          <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;text-align:center;">
            <div style="font-size:20px;font-weight:800;color:{'#ef4444' if data.get('failed_count',0) > 0 else '#94a3b8'};">{data.get('failed_count',0)}</div>
            <div style="font-size:11px;color:#94a3b8;margin-top:2px;">Respaldos Fallidos</div>
          </div>
        </td>
      </tr>
    </table>"""

    # 2. Resumen por Cliente / Tenant con Almacenamiento y Cuotas
    t_rows = ""
    for t in data.get('tenants_summary', []):
        t_col = "#10b981" if t['status'] == 'OK' else ("#f59e0b" if t['status'] == 'WARNING' else "#ef4444")
        t_rows += f"""
        <tr style="border-bottom:1px solid #334155;">
          <td style="padding:9px 12px;font-weight:600;color:#f8fafc;">{t['tenant_name']}</td>
          <td style="padding:9px 12px;text-align:center;color:#cbd5e1;">{t['total_vms']}</td>
          <td style="padding:9px 12px;text-align:center;font-weight:bold;color:{t_col};">{t['success_rate']}%</td>
          <td style="padding:9px 12px;text-align:center;font-weight:bold;color:#f8fafc;">{t['total_volume_str']}</td>
          <td style="padding:9px 12px;text-align:center;color:#94a3b8;font-size:11px;">{t['local_storage_str']}</td>
          <td style="padding:9px 12px;text-align:center;color:#38bdf8;font-size:11px;font-weight:bold;">{t['cloud_storage_str']}</td>
          <td style="padding:9px 12px;text-align:center;color:#a78bfa;font-size:11px;">{t['quota_str']}</td>
          <td style="padding:9px 12px;text-align:center;">
            <span style="background:{t_col}22;color:{t_col};padding:2px 8px;border-radius:4px;font-size:10px;font-weight:bold;">{t['status']}</span>
          </td>
        </tr>"""

    tenants_html = f"""
    <div style="margin-bottom:28px;border:1px solid #334155;border-radius:10px;overflow-x:auto;">
      <table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:12px;min-width:650px;">
        <thead>
          <tr style="background:#1e293b;color:#94a3b8;text-align:left;font-size:11px;">
            <th style="padding:10px 12px;">Cliente / Tenant</th>
            <th style="padding:10px 12px;text-align:center;">Equipos</th>
            <th style="padding:10px 12px;text-align:center;">Tasa Éxito</th>
            <th style="padding:10px 12px;text-align:center;">Almacenamiento Total</th>
            <th style="padding:10px 12px;text-align:center;">Local NTFS</th>
            <th style="padding:10px 12px;text-align:center;">Cloud Acronis</th>
            <th style="padding:10px 12px;text-align:center;">Cuota / Límite</th>
            <th style="padding:10px 12px;text-align:center;">Estado</th>
          </tr>
        </thead>
        <tbody>{t_rows}</tbody>
      </table>
    </div>"""

    # 3. Equipos en Riesgo o Afectados (Punto 3)
    risk = data.get('risk_summary', {})
    total_r = risk.get('total_risks', 0)
    risk_cards_html = ""
    if total_r > 0:
        items_html = ""
        for it in risk.get('no_history', []):
            items_html += f"""<li style="margin-bottom:6px;color:#fca5a5;"><strong>{it['name']}</strong> ({it['tenant']}) — {it['reason']}</li>"""
        for it in risk.get('overdue_48h', []):
            items_html += f"""<li style="margin-bottom:6px;color:#f87171;"><strong>{it['name']}</strong> ({it['tenant']}) — {it['reason']}</li>"""
        for it in risk.get('overdue_24h', []):
            items_html += f"""<li style="margin-bottom:6px;color:#fcd34d;"><strong>{it['name']}</strong> ({it['tenant']}) — {it['reason']}</li>"""
        for it in risk.get('no_plan', []):
            items_html += f"""<li style="margin-bottom:6px;color:#cbd5e1;"><strong>{it['name']}</strong> ({it['tenant']}) — {it['reason']}</li>"""

        risk_cards_html = f"""
        <div style="background:rgba(239,68,68,0.08);border:1px solid #ef444455;border-radius:10px;padding:16px;margin-bottom:28px;">
          <div style="display:flex;align-items:center;margin-bottom:10px;">
            <span style="background:#ef4444;color:#ffffff;font-size:11px;font-weight:bold;padding:3px 8px;border-radius:4px;margin-right:8px;">
              ⚠️ {total_r} CONDICIONES DE RIESGO DETECTADAS
            </span>
            <span style="font-size:12px;color:#cbd5e1;">Atención prioritaria requerida sobre los equipos seleccionados</span>
          </div>
          <ul style="margin:0;padding-left:20px;font-size:13px;color:#f1f5f9;">
            {items_html}
          </ul>
        </div>"""
    else:
        risk_cards_html = """
        <div style="background:rgba(16,185,129,0.1);border:1px solid #10b98144;border-radius:10px;padding:14px 18px;margin-bottom:28px;color:#10b981;font-size:13px;">
          ✅ <strong>Excelente:</strong> Todos los equipos seleccionados cuentan con respaldo al día, planes asignados y sin atrasos detectados.
        </div>"""

    # 4. Tabla Técnica de Servidores / BBDD Completa (Punto 2)
    srv_rows = ""
    for srv in data.get('servers_detail', []):
        age_col = "#10b981" if srv['age_status'] == 'ok' else ("#f59e0b" if srv['age_status'] == 'warn' else "#ef4444")
        st_col = "#10b981" if srv['status'] == 'OK' else ("#f59e0b" if srv['status'] == 'WARNING' else "#ef4444")
        cyb_score = srv['cyberfit']
        cyb_col = "#10b981" if cyb_score >= CYBERFIT_THR else ("#f59e0b" if cyb_score > 0 else "#64748b")

        act_id = srv.get('latest_activity_id') or ''
        vm_ident = srv.get('vm_id') or ''
        spd_badge = f'<div style="font-size:10px;color:#94a3b8;margin-top:2px;"><i class="fas fa-bolt" style="color:#eab308;font-size:9px;"></i> {srv.get("speed_str","")}</div>' if srv.get('speed_str') else ''

        srv_rows += f"""
        <tr style="border-bottom:1px solid #334155;">
          <td style="padding:10px 8px;font-weight:bold;color:#f8fafc;">
            <a href="javascript:void(0)" onclick="openActivityDetailsModal('{act_id}', '{vm_ident}')" style="color:#38bdf8;text-decoration:none;display:inline-flex;align-items:center;gap:4px;" title="Ver detalles precisos de actividad">
              {srv['name']} <span style="font-size:10px;opacity:0.75;">🔍</span>
            </a>
          </td>
          <td style="padding:10px 8px;color:#94a3b8;font-size:11px;">{srv['tenant_name']}</td>
          <td style="padding:10px 8px;color:#cbd5e1;font-size:11px;">{srv['plan_name']}</td>
          <td style="padding:10px 8px;text-align:center;font-size:11px;font-weight:bold;color:#f8fafc;white-space:nowrap;">{srv.get('backup_count_str', '0')}</td>
          <td style="padding:10px 8px;color:#cbd5e1;font-size:11px;">{srv['last_backup_formatted']}</td>
          <td style="padding:10px 8px;"><span style="color:{age_col};font-weight:bold;font-size:11px;">{srv['age_str']}</span></td>
          <td style="padding:10px 8px;text-align:center;color:#94a3b8;font-size:11px;font-weight:600;">{srv['size_local_str']}</td>
          <td style="padding:10px 8px;text-align:center;color:#38bdf8;font-size:11px;font-weight:bold;">{srv['size_cloud_str']}</td>
          <td style="padding:10px 8px;color:#a78bfa;font-size:11px;">{srv['duration_str']}{spd_badge}</td>
          <td style="padding:10px 8px;color:#94a3b8;font-size:11px;">{srv['next_backup_formatted']}</td>
          <td style="padding:10px 8px;color:#94a3b8;font-size:11px;">{srv['agent_version']}</td>
          <td style="padding:10px 8px;text-align:center;"><span style="color:{cyb_col};font-weight:bold;font-size:11px;">{cyb_score}</span></td>
          <td style="padding:10px 8px;text-align:center;"><span style="background:{st_col}22;color:{st_col};padding:2px 6px;border-radius:4px;font-size:10px;font-weight:bold;">{srv['status']}</span></td>
        </tr>"""

    tech_table_html = f"""
    <div style="margin-bottom:28px;border:1px solid #334155;border-radius:10px;overflow-x:auto;">
      <table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;font-size:12px;min-width:750px;">
        <thead>
          <tr style="background:#1e293b;color:#94a3b8;text-align:left;font-size:11px;">
            <th style="padding:10px 8px;">Equipo / VM</th>
            <th style="padding:10px 8px;">Cliente</th>
            <th style="padding:10px 8px;">Plan</th>
            <th style="padding:10px 8px;text-align:center;">Respaldos</th>
            <th style="padding:10px 8px;">Último Respaldo</th>
            <th style="padding:10px 8px;">Antigüedad</th>
            <th style="padding:10px 8px;text-align:center;">Local (NTFS)</th>
            <th style="padding:10px 8px;text-align:center;">Cloud Acronis</th>
            <th style="padding:10px 8px;">Duración</th>
            <th style="padding:10px 8px;">Próximo</th>
            <th style="padding:10px 8px;">Agente</th>
            <th style="padding:10px 8px;text-align:center;">CyberFit</th>
            <th style="padding:10px 8px;text-align:center;">Estado</th>
          </tr>
        </thead>
        <tbody>{srv_rows}</tbody>
      </table>
    </div>"""

    # 5. Capacidad de Almacenamiento
    storages = data.get('storages', [])
    storage_cards = ""
    for st in storages:
        pct = st['usage_percent']
        bar_color = "#ef4444" if pct >= 85 else ("#f59e0b" if pct >= 75 else "#10b981")
        alert_badge = ""
        if st['is_warning']:
            alert_badge = f"""<span style="background:#ef4444;color:#fff;font-size:10px;padding:2px 6px;border-radius:4px;font-weight:bold;margin-left:8px;">⚠️ RIESGO AGOTAMIENTO (&gt;{st['threshold']}%)</span>"""

        storage_cards += f"""
        <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px 18px;margin-bottom:12px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <div>
              <strong style="color:#ffffff;font-size:13px;">{st['name']}</strong>
              <span style="color:#60a5fa;font-size:11px;margin-left:8px;">({st['type_label']})</span>
              {alert_badge}
            </div>
            <span style="font-size:14px;font-weight:bold;color:{bar_color};">{pct:.1f}%</span>
          </div>
          <div style="background:#0f172a;border-radius:6px;height:8px;overflow:hidden;margin-bottom:8px;">
            <div style="background:{bar_color};width:{min(100.0, pct)}%;height:100%;border-radius:6px;"></div>
          </div>
          <div style="display:flex;justify-content:space-between;font-size:11px;color:#94a3b8;">
            <span>Total: <strong style="color:#f8fafc;">{st['total_str']}</strong></span>
            <span>Usado: <strong style="color:#f8fafc;">{st['used_str']}</strong></span>
            <span>Libre: <strong style="color:#f8fafc;">{st['free_str']}</strong></span>
            <span>Medido: {st['timestamp']}</span>
          </div>
        </div>"""

    # Ensamblado Final
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Reporte Ejecutivo de Respaldos - Backupcode</title>
  <style>
    {pdf_style}
  </style>
</head>
<body style="margin:0;padding:0;background-color:#080e1a;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#f1f5f9;">
  <table width="100%" cellspacing="0" cellpadding="0" style="background-color:#080e1a;padding:24px 0;">
    <tr>
      <td align="center">
        <table width="780" cellspacing="0" cellpadding="0" style="max-width:780px;width:100%;background-color:#0f172a;border:1px solid #334155;border-radius:14px;overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.5);">
          
          <!-- Header con Logo Backupcode -->
          <tr>
            <td style="padding:24px 28px;background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);border-bottom:2px solid #3b82f6;">
              <table width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  {logo_html}
                  <td style="vertical-align:middle;">
                    <span style="font-size:11px;font-weight:700;color:#60a5fa;letter-spacing:1px;text-transform:uppercase;">BACKUPCODE · SOLUCIONES IT</span>
                    <h1 style="margin:4px 0 2px 0;font-size:22px;color:#ffffff;font-weight:800;">Reporte Ejecutivo de Respaldos</h1>
                    <p style="margin:0;font-size:12px;color:#94a3b8;">Período evaluado: <strong>{data.get('period_start')}</strong> al <strong>{data.get('period_end')}</strong></p>
                    {scope_badge}
                  </td>
                  <td align="right" style="vertical-align:middle;">
                    <span style="display:inline-block;padding:8px 14px;background:#1e293b;border:1px solid #3b82f644;border-radius:8px;font-size:11px;color:#94a3b8;">
                      Generado: <strong style="color:#f8fafc;">{data.get('generated_at')}</strong> (Chile)
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:28px 32px;">

              <!-- 1. KPIs y Rendimiento -->
              <h2 style="margin:0 0 12px 0;font-size:14px;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;">1. Rendimiento y Volumen General</h2>
              {kpis_html}

              <!-- 2. Resumen por Cliente / Tenant -->
              <h2 style="margin:0 0 12px 0;font-size:14px;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;">2. Desglose Agrupado por Cliente / Tenant</h2>
              {tenants_html}

              <!-- 3. Equipos en Riesgo o Sin Protección -->
              <h2 style="margin:0 0 12px 0;font-size:14px;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;">3. Diagnóstico de Riesgo y Equipos Afectados</h2>
              {risk_cards_html}

              <!-- 4. Tabla Técnica de Servidores / BBDD -->
              <h2 style="margin:0 0 12px 0;font-size:14px;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;">4. Detalle Técnico por Equipo Seleccionado</h2>
              {tech_table_html}

              <!-- 5. Capacidad de Almacenamiento -->
              <h2 style="margin:0 0 12px 0;font-size:14px;color:#60a5fa;text-transform:uppercase;letter-spacing:0.5px;">5. Capacidad de Almacenamiento (Local NTFS & Cloud)</h2>
              <div style="margin-bottom:14px;">
                {storage_cards}
              </div>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:18px 32px;background-color:#080e1a;border-top:1px solid #334155;font-size:11px;color:#64748b;text-align:center;">
              Acronis VM Monitor &bull; Backupcode Soluciones IT &bull; Informe Ejecutivo Automatizado para Francisco y Pablo &bull; {data.get('generated_at')}
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
    return html


def render_report_pdf_html(data: dict) -> str:
    """
    Genera una plantilla HTML específicamente optimizada para exportación a PDF (A4 Landscape, tema ejecutivo claro,
    alto contraste y legibilidad absoluta para impresión y visualizadores PDF).
    """
    logo_b64 = get_backupcode_logo_base64()
    rate = data.get('success_rate', 100.0)
    rate_col = "#16a34a" if rate >= 95 else ("#d97706" if rate >= 80 else "#dc2626")

    # Scope badge
    is_filt = data.get('is_filtered_selection')
    scope_txt = f"Selección Personalizada ({data.get('total_machines',0)} equipos)" if is_filt else f"Todos los equipos visibles ({data.get('total_machines',0)})"

    # Logo HTML en cápsula oscura de alto contraste
    logo_html = f"""<div style="background:#090d16;padding:6px 12px;border-radius:6px;display:inline-block;">
      <img src="{logo_b64}" width="100" style="display:block;" alt="Backupcode" />
    </div>""" if logo_b64 else """<div style="font-size:14pt;font-weight:bold;color:#0284c7;">BACKUPCODE</div>"""

    # 1. KPIs
    kpis_html = f"""
    <table width="100%" cellspacing="4" cellpadding="0" style="margin-bottom:12px;">
      <tr>
        <td width="16%">
          <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:6px;padding:8px 4px;text-align:center;">
            <div style="font-size:15pt;font-weight:bold;color:#0f172a;">{data.get('total_machines',0)}</div>
            <div style="font-size:7.5pt;font-weight:bold;color:#64748b;text-transform:uppercase;margin-top:2px;">Equipos Evaluados</div>
          </div>
        </td>
        <td width="16%">
          <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:6px;padding:8px 4px;text-align:center;">
            <div style="font-size:15pt;font-weight:bold;color:{rate_col};">{data.get('success_rate',100.0)}%</div>
            <div style="font-size:7.5pt;font-weight:bold;color:#64748b;text-transform:uppercase;margin-top:2px;">Tasa de Éxito</div>
          </div>
        </td>
        <td width="20%">
          <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:6px;padding:8px 4px;text-align:center;">
            <div style="font-size:15pt;font-weight:bold;color:#0284c7;">{data.get('total_volume_str','0 GB')}</div>
            <div style="font-size:7.5pt;font-weight:bold;color:#64748b;text-transform:uppercase;margin-top:2px;">Volumen Total Procesado</div>
          </div>
        </td>
        <td width="16%">
          <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:6px;padding:8px 4px;text-align:center;">
            <div style="font-size:15pt;font-weight:bold;color:#7c3aed;">{data.get('avg_duration_str','< 1m')}</div>
            <div style="font-size:7.5pt;font-weight:bold;color:#64748b;text-transform:uppercase;margin-top:2px;">Duración Promedio</div>
          </div>
        </td>
        <td width="16%">
          <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:6px;padding:8px 4px;text-align:center;">
            <div style="font-size:15pt;font-weight:bold;color:#16a34a;">{data.get('success_count',0)}</div>
            <div style="font-size:7.5pt;font-weight:bold;color:#64748b;text-transform:uppercase;margin-top:2px;">Respaldos Exitosos</div>
          </div>
        </td>
        <td width="16%">
          <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:6px;padding:8px 4px;text-align:center;">
            <div style="font-size:15pt;font-weight:bold;color:{'#dc2626' if data.get('failed_count',0) > 0 else '#64748b'};">{data.get('failed_count',0)}</div>
            <div style="font-size:7.5pt;font-weight:bold;color:#64748b;text-transform:uppercase;margin-top:2px;">Respaldos Fallidos</div>
          </div>
        </td>
      </tr>
    </table>"""

    # 2. Desglose por Cliente
    t_rows = ""
    for t in data.get('tenants_summary', []):
        st = t['status']
        badge_cls = "badge-ok" if st == 'OK' else ("badge-warn" if st == 'WARNING' else "badge-crit")
        t_rows += f"""
        <tr>
          <td style="font-weight:bold;color:#0f172a;">{t['tenant_name']}</td>
          <td style="text-align:center;">{t['total_vms']}</td>
          <td style="text-align:center;font-weight:bold;color:{'#16a34a' if t['success_rate']>=90 else '#d97706'};">{t['success_rate']}%</td>
          <td style="text-align:center;font-weight:bold;color:#0f172a;">{t['total_volume_str']}</td>
          <td style="text-align:center;color:#64748b;">{t['local_storage_str']}</td>
          <td style="text-align:center;font-weight:bold;color:#0284c7;">{t['cloud_storage_str']}</td>
          <td style="text-align:center;color:#475569;">{t['quota_str']}</td>
          <td style="text-align:center;"><span class="{badge_cls}">{st}</span></td>
        </tr>"""

    tenants_html = f"""
    <table class="data-table" cellspacing="0" cellpadding="0">
      <thead>
        <tr>
          <th width="24%">Cliente / Tenant</th>
          <th width="8%" style="text-align:center;">Equipos</th>
          <th width="10%" style="text-align:center;">Tasa Éxito</th>
          <th width="14%" style="text-align:center;">Almacenamiento Total</th>
          <th width="12%" style="text-align:center;">Local NTFS</th>
          <th width="12%" style="text-align:center;">Cloud Acronis</th>
          <th width="12%" style="text-align:center;">Cuota / Límite</th>
          <th width="8%" style="text-align:center;">Estado</th>
        </tr>
      </thead>
      <tbody>{t_rows}</tbody>
    </table>"""

    # 3. Riesgos
    risk = data.get('risk_summary', {})
    total_r = risk.get('total_risks', 0)
    if total_r > 0:
        items_html = ""
        for it in risk.get('no_history', []):
            items_html += f"""<li style="margin-bottom:3px;color:#991b1b;"><strong>{it['name']}</strong> ({it['tenant']}) — {it['reason']}</li>"""
        for it in risk.get('overdue_48h', []):
            items_html += f"""<li style="margin-bottom:3px;color:#b91c1c;"><strong>{it['name']}</strong> ({it['tenant']}) — {it['reason']}</li>"""
        for it in risk.get('overdue_24h', []):
            items_html += f"""<li style="margin-bottom:3px;color:#b45309;"><strong>{it['name']}</strong> ({it['tenant']}) — {it['reason']}</li>"""
        for it in risk.get('no_plan', []):
            items_html += f"""<li style="margin-bottom:3px;color:#475569;"><strong>{it['name']}</strong> ({it['tenant']}) — {it['reason']}</li>"""

        risk_html = f"""
        <div style="background:#fef2f2;border:1px solid #f87171;border-radius:6px;padding:8px 12px;margin-bottom:12px;">
          <div style="font-weight:bold;color:#991b1b;font-size:8.5pt;margin-bottom:4px;">
            ATENCIÓN: {total_r} CONDICIONES DE RIESGO DETECTADAS
          </div>
          <ul style="margin:0;padding-left:16px;font-size:7.5pt;">
            {items_html}
          </ul>
        </div>"""
    else:
        risk_html = """
        <div style="background:#f0fdf4;border:1px solid #86efac;border-radius:6px;padding:7px 12px;margin-bottom:12px;color:#166534;font-size:8pt;">
          <strong>Excelente:</strong> Todos los equipos evaluados cuentan con respaldo al día y políticas activas.
        </div>"""

    # 4. Detalle Técnico
    srv_rows = ""
    for srv in data.get('servers_detail', []):
        st = srv['status']
        badge_cls = "badge-ok" if st == 'OK' else ("badge-warn" if st == 'WARNING' else "badge-crit")
        b_cnt = srv.get('backup_count_str', '0').replace('✅', 'OK').replace('❌', 'FAIL').replace('⚠️', 'WARN')

        spd_pdf = f"<br/><span style='font-size:6.5pt;color:#7c3aed;'>{srv.get('speed_str','')}</span>" if srv.get('speed_str') else ""

        srv_rows += f"""
        <tr>
          <td style="font-weight:bold;color:#0f172a;">{srv['name']}</td>
          <td style="color:#475569;">{srv['tenant_name']}</td>
          <td style="color:#334155;">{srv['plan_name']}</td>
          <td style="text-align:center;font-weight:bold;">{b_cnt}</td>
          <td>{srv['last_backup_formatted']}</td>
          <td style="font-weight:bold;color:{'#16a34a' if srv['age_status']=='ok' else ('#d97706' if srv['age_status']=='warn' else '#dc2626')};">{srv['age_str']}</td>
          <td style="text-align:center;color:#64748b;">{srv['size_local_str']}</td>
          <td style="text-align:center;font-weight:bold;color:#0284c7;">{srv['size_cloud_str']}</td>
          <td style="color:#7c3aed;">{srv['duration_str']}{spd_pdf}</td>
          <td style="color:#64748b;">{srv['next_backup_formatted']}</td>
          <td style="color:#64748b;">{srv['agent_version']}</td>
          <td style="text-align:center;font-weight:bold;">{srv['cyberfit']}</td>
          <td style="text-align:center;"><span class="{badge_cls}">{st}</span></td>
        </tr>"""

    tech_table_html = f"""
    <table class="data-table" cellspacing="0" cellpadding="0">
      <thead>
        <tr>
          <th width="16%">Equipo / VM</th>
          <th width="15%">Cliente</th>
          <th width="12%">Plan</th>
          <th width="8%" style="text-align:center;">Respaldos</th>
          <th width="9%">Último Respaldo</th>
          <th width="7%">Antigüedad</th>
          <th width="7%" style="text-align:center;">Local NTFS</th>
          <th width="8%" style="text-align:center;">Cloud Acronis</th>
          <th width="6%">Duración</th>
          <th width="8%">Próximo</th>
          <th width="5%">Agente</th>
          <th width="4%" style="text-align:center;">Score</th>
          <th width="5%" style="text-align:center;">Estado</th>
        </tr>
      </thead>
      <tbody>{srv_rows}</tbody>
    </table>"""

    # 5. Capacidad de Almacenamiento
    storage_rows = ""
    for st in data.get('storages', []):
        pct = st['usage_percent']
        bar_col = "#dc2626" if pct >= 85 else ("#d97706" if pct >= 75 else "#16a34a")
        warn_txt = " [ALERTA AGOTAMIENTO]" if st['is_warning'] else ""

        storage_rows += f"""
        <div style="background:#f8fafc;border:1px solid #cbd5e1;border-radius:6px;padding:6px 10px;margin-bottom:6px;">
          <table width="100%" cellspacing="0" cellpadding="0">
            <tr>
              <td style="font-size:8pt;font-weight:bold;color:#0f172a;">
                {st['name']} <span style="font-weight:normal;color:#0284c7;">({st['type_label']})</span>
                <span style="color:#dc2626;font-size:7.5pt;font-weight:bold;">{warn_txt}</span>
              </td>
              <td style="text-align:right;font-size:8.5pt;font-weight:bold;color:{bar_col};">
                {pct:.1f}%
              </td>
            </tr>
          </table>
          <div style="background:#e2e8f0;height:6px;border-radius:3px;margin:3px 0;">
            <div style="background:{bar_col};width:{min(100.0, pct):.1f}%;height:6px;border-radius:3px;"></div>
          </div>
          <table width="100%" cellspacing="0" cellpadding="0" style="font-size:7pt;color:#64748b;">
            <tr>
              <td>Total: <strong>{st['total_str']}</strong></td>
              <td>Usado: <strong>{st['used_str']}</strong></td>
              <td>Libre: <strong>{st['free_str']}</strong></td>
              <td style="text-align:right;">Medido: {st['timestamp']}</td>
            </tr>
          </table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<style>
  @page {{
    size: a4 landscape;
    margin: 8mm 10mm 10mm 10mm;
  }}
  body {{
    font-family: Helvetica, Arial, sans-serif;
    color: #0f172a;
    background-color: #ffffff;
    font-size: 8pt;
    line-height: 1.3;
  }}
  .header-table {{
    width: 100%;
    border-bottom: 2.5px solid #0284c7;
    margin-bottom: 12px;
    padding-bottom: 8px;
  }}
  .section-title {{
    font-size: 9.5pt;
    font-weight: bold;
    color: #0369a1;
    margin: 12px 0 5px 0;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 3px;
  }}
  table.data-table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 10px;
  }}
  table.data-table th {{
    background: #0f172a;
    color: #ffffff;
    font-size: 7.5pt;
    font-weight: bold;
    padding: 5px 6px;
    border: 1px solid #0f172a;
    text-align: left;
  }}
  table.data-table td {{
    padding: 4px 6px;
    border: 1px solid #cbd5e1;
    font-size: 7.5pt;
    color: #1e293b;
  }}
  table.data-table tr:nth-child(even) td {{
    background: #f8fafc;
  }}
  .badge-ok {{
    background: #dcfce7;
    color: #166534;
    font-weight: bold;
    padding: 2px 5px;
    border-radius: 3px;
    font-size: 7pt;
  }}
  .badge-warn {{
    background: #fef3c7;
    color: #92400e;
    font-weight: bold;
    padding: 2px 5px;
    border-radius: 3px;
    font-size: 7pt;
  }}
  .badge-crit {{
    background: #fee2e2;
    color: #991b1b;
    font-weight: bold;
    padding: 2px 5px;
    border-radius: 3px;
    font-size: 7pt;
  }}
  tr {{
    page-break-inside: avoid;
  }}
</style>
</head>
<body>
  <!-- Header Corporativo -->
  <table class="header-table" cellspacing="0" cellpadding="0">
    <tr>
      <td width="115" style="vertical-align:middle;">
        {logo_html}
      </td>
      <td style="vertical-align:middle;padding-left:14px;">
        <div style="font-size:8.5pt;font-weight:bold;color:#0284c7;letter-spacing:1px;text-transform:uppercase;">BACKUPCODE · SOLUCIONES IT</div>
        <div style="font-size:16pt;font-weight:bold;color:#0f172a;margin:2px 0 0 0;">Informe Ejecutivo de Respaldos</div>
        <div style="font-size:8.5pt;color:#64748b;">Monitoreo Acronis Cyber Protect · Estado de Protección, Capacidad y Cuotas</div>
      </td>
      <td style="vertical-align:middle;text-align:right;width:240px;">
        <div style="font-size:8pt;color:#475569;line-height:1.4;">
          <div>Período: <strong>{data.get('period_start')}</strong> al <strong>{data.get('period_end')}</strong></div>
          <div>Alcance: <strong>{scope_txt}</strong></div>
          <div>Generado: <strong>{data.get('generated_at')} (Chile)</strong></div>
        </div>
      </td>
    </tr>
  </table>

  <!-- 1. KPIs -->
  <div class="section-title">1. Rendimiento y Volumen General</div>
  {kpis_html}

  <!-- 2. Clientes -->
  <div class="section-title">2. Desglose Agrupado por Cliente / Tenant</div>
  {tenants_html}

  <!-- 3. Riesgos -->
  <div class="section-title">3. Diagnóstico de Riesgo y Equipos Afectados</div>
  {risk_html}

  <!-- 4. Detalle Técnico -->
  <div class="section-title">4. Detalle Técnico por Equipo Seleccionado</div>
  {tech_table_html}

  <!-- 5. Almacenamiento -->
  <div class="section-title">5. Capacidad de Almacenamiento (Local NTFS & Cloud)</div>
  {storage_rows}

  <!-- Footer -->
  <table width="100%" cellspacing="0" cellpadding="0" style="border-top:1px solid #cbd5e1;padding-top:6px;margin-top:12px;font-size:7.5pt;color:#64748b;">
    <tr>
      <td>Acronis VM Monitor &bull; Backupcode Soluciones IT &bull; Documento Confidencial</td>
      <td style="text-align:right;">Página <pdf:pageNumber /> de <pdf:pageCount /></td>
    </tr>
  </table>
</body>
</html>"""
    return html


def generate_report_pdf(data: dict) -> bytes:
    """
    Genera un archivo binario PDF a partir del informe en HTML usando xhtml2pdf
    con diseño apaisado de alto contraste y legibilidad ejecutiva.
    """
    import io
    import xhtml2pdf.pisa as pisa

    html = render_report_pdf_html(data)
    pdf_buffer = io.BytesIO()
    status = pisa.CreatePDF(io.StringIO(html), dest=pdf_buffer, encoding='utf-8')
    if status.err:
        raise RuntimeError(f"Error generando PDF: código {status.err}")
    return pdf_buffer.getvalue()


def send_weekly_report(recipients: list = None, start_iso: str = None, end_iso: str = None, tenant_id: str = None, vm_ids: list = None) -> dict:
    """Genera y despacha el reporte semanal por correo a los destinatarios indicados."""
    cfg = db.get_report_config()
    to_emails = recipients or cfg.get('emails') or TO_EMAILS

    if not to_emails:
        return {'ok': False, 'error': 'No hay correos destinatarios configurados'}

    data = generate_weekly_report_data(start_iso, end_iso, tenant_id, vm_ids=vm_ids)
    html_body = render_report_html(data)

    rate = data.get('success_rate', 100.0)
    rate_icon = "🟢" if rate >= 95 else ("🟡" if rate >= 80 else "🔴")
    subject = f"📊 [Reporte Acronis] {rate_icon} {rate:.1f}% Éxito ({data.get('total_machines')} equipos) - {data.get('period_start')}"

    email_cfg = dict(db.get_channel_config('email'))
    email_cfg['to_emails'] = to_emails
    email_cfg['enabled'] = True

    sent = send_email(subject, html_body, force_cfg=email_cfg)
    return {
        'ok': sent,
        'recipients': to_emails,
        'subject': subject,
        'report_data': data
    }


def check_scheduled_weekly_report():
    """
    Evalúa si corresponde enviar automáticamente el reporte semanal según la
    configuración (ej. los días lunes a las 08:00 AM hora de Chile).
    """
    cfg = db.get_report_config()
    if not cfg.get('enabled'):
        return

    now_c = now_chile()
    day_map = {0: 'mon', 1: 'tue', 2: 'wed', 3: 'thu', 4: 'fri', 5: 'sat', 6: 'sun'}
    current_day = day_map.get(now_c.weekday())
    target_day = (cfg.get('day_of_week') or 'mon').lower()

    current_hm = now_c.strftime('%H:%M')
    target_hm = cfg.get('time_utc4') or '08:00'
    today_str = now_c.strftime('%Y-%m-%d')

    if current_day == target_day and current_hm >= target_hm:
        if cfg.get('last_sent_date') != today_str:
            target_vms = cfg.get('selected_vm_ids')
            print(f"\n[REPORT SCHEDULER] Disparando envío automático del reporte para {cfg.get('emails')}...")
            res = send_weekly_report(recipients=cfg.get('emails'), vm_ids=target_vms)
            if res.get('ok'):
                print(f"[REPORT SCHEDULER] ✅ Reporte enviado exitosamente a {res.get('recipients')}")
                cfg['last_sent_date'] = today_str
                db.set_report_config(cfg)
            else:
                print(f"[REPORT SCHEDULER] ❌ Falló el envío del reporte: {res.get('error')}")


# ─────────────────────────── Ciclo principal ───────────────────────────────

def run():
    db.init_db()

    email_cfg = db.get_channel_config('email')
    email_active = bool(email_cfg.get('enabled') or (SMTP_HOST and TO_EMAILS))

    rep_cfg = db.get_report_config()

    print(f"\n{'='*60}")
    print(f"  Acronis Notification Engine")
    print(f"  Intervalo      : {NOTIFY_INTERVAL}s")
    print(f"  Re-notificación: cada {REMIND_INTERVAL_H}h")
    print(f"  Backup warning : >{BACKUP_WARN_H}h  |  critical: >{BACKUP_CRIT_H}h")
    print(f"  CyberFit mín   : {CYBERFIT_THR}")
    print(f"  Telegram       : {'✅ configurado' if (TELEGRAM_BOT_TOKEN or db.get_channel_config('telegram').get('enabled')) else '❌ NO configurado'}")
    print(f"  Email SMTP     : {'✅ configurado' if email_active else '❌ NO configurado'}")
    print(f"  Backup Exitoso : {'✅ activo' if NOTIFY_BACKUP_SUCCESS else '❌ desactivado'}")
    print(f"  Reporte Semanal: {'✅ activo (' + rep_cfg.get('day_of_week', 'mon').upper() + ' ' + rep_cfg.get('time_utc4','08:00') + ')' if rep_cfg.get('enabled') else '❌ desactivado'}")
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

            # 3. Comprobar programación del Reporte Semanal
            check_scheduled_weekly_report()

            # 4. Resumen de notificaciones activas
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
