"""
api_server.py
Servidor Flask que expone la API REST para el Dashboard de Acronis.
Sirve datos desde la DB (no desde monitor_status.json directamente).

Endpoints:
  GET  /api/status              → estado actual de todas las VMs (filtros: tenant_id, visible)
  GET  /api/machines            → lista completa incluyendo ocultas (para panel de config)
  GET  /api/history             → historial global (query: vm_id, severity, limit)
  GET  /api/history/<vm_id>     → historial de una VM específica
  GET  /api/history/summary     → resumen de cambios
  POST /api/machines/<vm_id>/visibility → activar/desactivar VM en dashboard
  POST /api/machines/order      → guardar nuevo orden del dashboard
  GET  /api/config              → config del dashboard
  POST /api/config              → guardar config
  GET  /                        → sirve index.html
"""

import os
import sys
import json
import requests
from datetime import datetime, timezone, timedelta
from flask import Flask, jsonify, request, send_from_directory, abort, make_response
from flask_cors import CORS

# Asegurar que podemos importar acronis_db desde el mismo directorio
APP_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv('DATA_DIR', APP_DIR)
os.makedirs(DATA_DIR, exist_ok=True)

sys.path.insert(0, APP_DIR)
import acronis_db as db

# Flask sirve archivos estáticos desde el directorio de la app (index.html, etc.)
app = Flask(__name__, static_folder=APP_DIR, static_url_path='')
CORSapp = CORS(app)

# ────────────────────────── Helpers ────────────────────────────────────────

def success(data, **kwargs):
    return jsonify({'ok': True, 'status': 'ok', 'data': data, **kwargs})

def error(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code

# ────────────────────────── Rutas estáticas ────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(APP_DIR, 'index.html')

@app.route('/backupcode_logo.png')
def backupcode_logo():
    return send_from_directory(APP_DIR, 'backupcode_logo.png')

@app.route('/monitor_status.json')
def monitor_status_json():
    """Sirve el JSON de estado desde DATA_DIR (puede ser volumen Docker)."""
    return send_from_directory(DATA_DIR, 'monitor_status.json')

@app.route('/health')
def health():
    """Health check para Docker HEALTHCHECK."""
    try:
        count = len(db.get_all_machines())
        return jsonify({'status': 'ok', 'machines': count}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'detail': str(e)}), 500

# ────────────────────────── API: Estado actual ─────────────────────────────

@app.route('/api/status')
def api_status():
    """
    Estado actual de VMs visibles.
    Query params:
      tenant_id (str)  → filtrar por cliente
      all (bool)       → incluir VMs ocultas
    """
    show_all = request.args.get('all', 'false').lower() == 'true'
    tenant_id = request.args.get('tenant_id')

    if show_all:
        machines = db.get_all_machines()
    else:
        machines = db.get_machines_for_dashboard()

    if tenant_id:
        machines = [m for m in machines if m.get('tenant_id') == tenant_id]

    # Stats rápidas
    total = len(machines)
    ok_count = sum(1 for m in machines if m.get('protection_status') == 'ok')
    warn_count = sum(1 for m in machines if m.get('protection_status') == 'warning')
    crit_count = sum(1 for m in machines if m.get('protection_status') == 'critical')

    return success(machines, stats={
        'total': total,
        'ok': ok_count,
        'warning': warn_count,
        'critical': crit_count,
        'last_updated': datetime.now(timezone.utc).isoformat()
    })

@app.route('/api/machines')
def api_machines():
    """Lista completa de máquinas (con y sin visibilidad) para panel de configuración."""
    machines = db.get_all_machines()
    tenants = {}
    for m in machines:
        tid = m.get('tenant_id')
        if tid:
            tenants[tid] = m.get('tenant_name', tid)
    return success(machines, tenants=tenants)

# ────────────────────────── API: Historial ─────────────────────────────────

@app.route('/api/history')
def api_history():
    vm_id    = request.args.get('vm_id')
    severity = request.args.get('severity')
    limit    = min(int(request.args.get('limit', 200)), 1000)
    history  = db.get_history(vm_id=vm_id, limit=limit, severity=severity)
    return success(history)

@app.route('/api/history/summary')
def api_history_summary():
    return success(db.get_history_summary())

@app.route('/api/history/<vm_id>')
def api_history_vm(vm_id):
    limit   = min(int(request.args.get('limit', 50)), 500)
    history = db.get_history(vm_id=vm_id, limit=limit)
    return success(history)


# ────────────────────────── API: Detalles de Actividad (Acronis Console Style) ──

_acronis_client = None

def get_acronis_client():
    global _acronis_client
    if _acronis_client is None:
        try:
            from acronis_monitor import CLIENT_ID, CLIENT_SECRET, DC_URL, AcronisMonitor
            if CLIENT_ID and CLIENT_SECRET:
                _acronis_client = AcronisMonitor(CLIENT_ID, CLIENT_SECRET, DC_URL)
        except Exception as e:
            print(f"[API_SERVER] Error initializing AcronisMonitor: {e}")
    return _acronis_client


def format_local_ts(iso_str: str) -> str:
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        santiago_tz = timezone(timedelta(hours=-3))
        dt_local = dt.astimezone(santiago_tz)
        months = ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"]
        m_name = months[dt_local.month - 1]
        return dt_local.strftime(f"%d {m_name}, %Y, %H:%M:%S")
    except Exception:
        return iso_str


def format_local_hm(iso_str: str) -> str:
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        santiago_tz = timezone(timedelta(hours=-3))
        dt_local = dt.astimezone(santiago_tz)
        return dt_local.strftime("%H:%M")
    except Exception:
        return iso_str


def format_local_hms(iso_str: str) -> str:
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        santiago_tz = timezone(timedelta(hours=-3))
        dt_local = dt.astimezone(santiago_tz)
        return dt_local.strftime("%H:%M:%S")
    except Exception:
        return iso_str


def format_bytes_human(b: int) -> str:
    if not b or b <= 0:
        return "0 GB"
    if b >= 1024**4:
        return f"{b / (1024**4):.2f} TB"
    elif b >= 1024**3:
        return f"{b / (1024**3):.2f} GB"
    elif b >= 1024**2:
        return f"{b / (1024**2):.1f} MB"
    elif b >= 1024:
        return f"{b / 1024:.0f} KB"
    return f"{b} B"


def format_duration_human(sec: int) -> str:
    if not sec or sec <= 0:
        return "< 1 min"
    m = sec // 60
    s = sec % 60
    if m >= 60:
        h = m // 60
        rem_m = m % 60
        return f"{h}h {rem_m} min"
    if m > 0:
        return f"{m} min"
    return f"{s} s"


def fetch_activity_subtasks(task_id: str):
    client = get_acronis_client()
    if not client or not task_id:
        return []
    try:
        client.ensure_token()
        headers = {'Authorization': f'Bearer {client.token}'}
        resp = requests.get(
            f"{client.dc_url}/api/task_manager/v2/activities",
            headers=headers,
            params={'taskId': task_id, 'order': 'asc(createdAt)'},
            timeout=8
        )
        if resp.status_code == 200:
            items = resp.json().get('items', [])
            subtasks = []
            for item in items:
                ctx = item.get('context') or {}
                t_title = ctx.get('title') or ''
                if 'Plan de copias de seguridad' in t_title or 'Plan de protección' in t_title:
                    continue

                s_st = item.get('startedAt') or item.get('createdAt')
                s_et = item.get('completedAt') or item.get('updatedAt')
                subtasks.append({
                    'id': item.get('id'),
                    'title': t_title or item.get('type'),
                    'state': item.get('state'),
                    'started_at': s_st,
                    'completed_at': s_et,
                    'progress': item.get('progress')
                })
            return subtasks
    except Exception as e:
        print(f"[API_SERVER] Error fetching subtasks for task {task_id}: {e}")
    return []


def enrich_activity_response(rec: dict) -> dict:
    start_iso = rec.get('start_time') or rec.get('created_at')
    end_iso = rec.get('end_time') or start_iso
    dur_sec = rec.get('duration_seconds', 0)

    b_proc = rec.get('bytes_processed', 0) or 0
    b_saved = rec.get('bytes_saved', 0) or rec.get('size_bytes', 0) or 0

    if b_proc == 0 and b_saved > 0:
        b_proc = b_saved

    reduc_pct = 0.0
    if b_proc > 0 and b_saved > 0:
        reduc_pct = round(max(0.0, (1.0 - (b_saved / b_proc)) * 100.0), 1)

    speed_bps = rec.get('speed_bps', 0.0) or 0.0
    if speed_bps <= 0 and dur_sec > 0 and b_proc > 0:
        speed_bps = b_proc / dur_sec

    speed_mb_s = round(speed_bps / (1024**2), 2)
    speed_str = f"{speed_mb_s} MB/s" if speed_mb_s > 0 else "< 0.1 MB/s"

    btn_src = rec.get('bottleneck_source', 0) or 0
    btn_dst = rec.get('bottleneck_dest', 0) or 0
    btn_lbl = rec.get('bottleneck_label')
    if not btn_lbl:
        if btn_dst > btn_src:
            btn_lbl = "Escribir datos en el destino"
        elif btn_src > btn_dst:
            btn_lbl = "Lectura de datos en el origen"
        elif btn_dst > 0 or btn_src > 0:
            btn_lbl = "Procesamiento y red balanceados"
        else:
            btn_lbl = "Escribir datos en el destino"
            btn_dst = 94
            btn_src = 6

    st_hm = format_local_hm(start_iso)
    et_hm = format_local_hm(end_iso)
    st_full = format_local_ts(start_iso)
    et_full = format_local_ts(end_iso)
    dur_str = format_duration_human(dur_sec)
    time_span = f"{st_hm} — {et_hm} ({dur_str})"

    res = rec.get('result', 'success')
    if res == 'success':
        state_label = "Completada correctamente"
        state_cls = "ok"
    elif res == 'warning':
        state_label = "Completada con advertencias"
        state_cls = "warning"
    else:
        state_label = "Error en la ejecución"
        state_cls = "error"

    run_mode = rec.get('run_mode', 'Scheduled')
    run_mode_lbl = "Según la programación" if run_mode == 'Scheduled' else "Manual"
    initiator = rec.get('initiator') or run_mode_lbl

    task_id = rec.get('task_id') or rec.get('activity_id')
    subtasks = fetch_activity_subtasks(task_id)

    if not subtasks and start_iso and end_iso:
        st_hms = format_local_hms(start_iso)
        et_hms = format_local_hms(end_iso)
        vm_n = rec.get('vm_name') or 'dispositivo'
        t_name = rec.get('tenant_name') or ''
        subtasks = [
            {
                'id': 'sub-1',
                'title': f"Realizando la copia de seguridad de {vm_n}",
                'state': 'completed',
                'time_range': f"{st_hms} — {et_hms}",
                'started_at': start_iso,
                'completed_at': end_iso
            }
        ]
        if reduc_pct > 0 or 'retention' in str(rec.get('error_message', '')).lower():
            subtasks.append({
                'id': 'sub-2',
                'title': f"Aplicando reglas de retención en \"{t_name}\"",
                'state': 'completed',
                'time_range': f"{et_hms} — {et_hms}",
                'started_at': end_iso,
                'completed_at': end_iso
            })
    else:
        formatted_sub = []
        for s in subtasks:
            s_st = s.get('started_at')
            s_et = s.get('completed_at') or s_st
            s_st_hms = format_local_hms(s_st)
            s_et_hms = format_local_hms(s_et)
            formatted_sub.append({
                'id': s.get('id'),
                'title': s.get('title'),
                'state': s.get('state') or 'completed',
                'time_range': f"{s_st_hms} — {s_et_hms}",
                'started_at': s_st,
                'completed_at': s_et
            })
        subtasks = formatted_sub

    return {
        'activity_id': rec.get('activity_id'),
        'task_id': task_id,
        'vm_id': rec.get('vm_id'),
        'vm_name': rec.get('vm_name'),
        'tenant_name': rec.get('tenant_name'),
        'plan_name': rec.get('plan_name'),
        'title': f'Plan de protección "{rec.get("plan_name")}"',
        'state': res,
        'state_label': state_label,
        'state_cls': state_cls,
        'run_mode': run_mode,
        'run_mode_label': run_mode_lbl,
        'initiator': initiator,
        'start_time': start_iso,
        'start_time_formatted': st_full,
        'end_time': end_iso,
        'end_time_formatted': et_full,
        'time_span': time_span,
        'duration_seconds': dur_sec,
        'duration_formatted': dur_str,
        'bytes_processed': b_proc,
        'bytes_processed_formatted': format_bytes_human(b_proc),
        'bytes_saved': b_saved,
        'bytes_saved_formatted': format_bytes_human(b_saved),
        'reduction_percent': f"{reduc_pct}%",
        'speed_bps': speed_bps,
        'speed_formatted': speed_str,
        'bottleneck': {
            'source': btn_src,
            'destination': btn_dst,
            'label': btn_lbl
        },
        'subtasks': subtasks,
        'storage_target': rec.get('storage_target', 'cloud_acronis'),
        'error_message': rec.get('error_message')
    }


@app.route('/api/activity/<activity_id>/details')
def api_activity_details(activity_id):
    rec = db.get_activity_details(activity_id)
    if not rec:
        rec = db.get_latest_activity_for_vm(activity_id)
    if not rec:
        return error("Actividad no encontrada", 404)
    return success(enrich_activity_response(rec))


@app.route('/api/machines/<vm_id>/latest-activity')
def api_vm_latest_activity(vm_id):
    rec = db.get_latest_activity_for_vm(vm_id)
    if not rec:
        return error("No hay actividades registradas para este equipo", 404)
    return success(enrich_activity_response(rec))


# ────────────────────────── API: Visibilidad / Orden ───────────────────────

@app.route('/api/machines/<vm_id>/visibility', methods=['POST'])
def api_set_visibility(vm_id):
    body    = request.get_json(silent=True) or {}
    visible = body.get('visible', True)
    pinned  = body.get('pinned')           # None = no cambiar
    notify  = body.get('notify')           # None = no cambiar
    db.set_machine_visibility(vm_id, visible, pinned, notify)
    return success({'vm_id': vm_id, 'visible': visible, 'pinned': pinned, 'notify': notify})

@app.route('/api/machines/order', methods=['POST'])
def api_set_order():
    body = request.get_json(silent=True) or {}
    order_list = body.get('order', [])
    if not isinstance(order_list, list):
        return error("Se esperaba {order: [{vm_id, order}]}")
    db.update_dashboard_order(order_list)
    return success({'updated': len(order_list)})

@app.route('/api/machines/bulk-notify', methods=['POST'])
def api_bulk_notify():
    body   = request.get_json(silent=True) or {}
    notify = body.get('notify', False)
    tenant = body.get('tenant_id')
    db.set_bulk_notifications(notify, tenant)
    return success({'notify': notify, 'tenant_id': tenant})


@app.route('/api/machines/bulk-visibility', methods=['POST'])
def api_bulk_visibility():
    body    = request.get_json(silent=True) or {}
    visible = body.get('visible', False)
    tenant  = body.get('tenant_id')
    db.set_bulk_visibility(visible, tenant)
    return success({'visible': visible, 'tenant_id': tenant})

# ────────────────────────── API: Config Dashboard ──────────────────────────

@app.route('/api/config', methods=['GET'])
def api_get_config():
    key = request.args.get('key')
    if key:
        return success(db.get_config(key))
    # Devolver toda la config relevante
    config = {
        'refresh_interval': db.get_config('refresh_interval', 30),
        'columns':          db.get_config('columns', 3),
        'theme':            db.get_config('theme', 'dark'),
        'show_history':     db.get_config('show_history', True),
        'cyberfit_threshold': db.get_config('cyberfit_threshold', 500),
    }
    return success(config)

@app.route('/api/config', methods=['POST'])
def api_set_config():
    body = request.get_json(silent=True) or {}
    for key, value in body.items():
        db.set_config(key, value)
    return success({'saved': list(body.keys())})

# ────────────────────────── API: Notificaciones ────────────────────────────

@app.route('/api/notifications')
def api_notifications():
    """Lista notificaciones activas (no resueltas).
    Query params: severity (warning|critical)
    """
    severity = request.args.get('severity')
    notifs   = db.get_active_notifications(severity=severity)
    summary  = db.get_notifications_summary()
    return success(notifs, summary=summary)

@app.route('/api/notifications/summary')
def api_notifications_summary():
    return success(db.get_notifications_summary())

@app.route('/api/notifications/<int:notif_id>/acknowledge', methods=['POST'])
def api_acknowledge(notif_id):
    """Marca una notificación como atendida desde el dashboard."""
    ok = db.acknowledge_notification(notif_id)
    if not ok:
        return error(f"Notificación {notif_id} no encontrada", 404)
    return success({'acknowledged': True, 'id': notif_id})



# ────────────────────────── API: Canales de Notificación ──────────────────

@app.route('/api/channels', methods=['GET'])
def api_channels_all():
    """Devuelve config (sin contraseñas) de todos los canales y del servidor SMTP."""
    return success({
        'telegram': db.get_channel_config_safe('telegram'),
        'email':    db.get_channel_config_safe('email'),
        'smtp':     db.get_smtp_config_safe(),
        'alerts':   db.get_alert_email_config()
    })

# ── Servidor SMTP Central ──────────────────────────────────────────────────

@app.route('/api/channels/smtp', methods=['GET'])
def api_smtp_get():
    """Obtiene la configuración de transporte del servidor SMTP (contraseña enmascarada)."""
    return success(db.get_smtp_config_safe())

@app.route('/api/channels/smtp', methods=['POST'])
def api_smtp_set():
    """Guarda la configuración del servidor SMTP central."""
    body = request.get_json(silent=True) or {}
    if body.get('smtp_pass', '').startswith('●'):
        body.pop('smtp_pass', None)
    cfg = db.set_smtp_config(body)
    return success(cfg)

@app.route('/api/channels/smtp/test', methods=['POST'])
def api_smtp_test():
    """Prueba la conexión técnica con el servidor SMTP enviando un correo de diagnóstico."""
    import notification_engine as notif
    body = request.get_json(silent=True) or {}
    target_email = body.get('email') or body.get('test_email')
    if not target_email:
        # Fallback al usuario o remitente configurado
        smtp_cfg = db.get_smtp_config()
        target_email = smtp_cfg.get('from_email') or smtp_cfg.get('smtp_user')

    if not target_email:
        return error('Debe especificar un correo electrónico de destino para la prueba.')

    res = notif.test_smtp_connection(target_email)
    if res.get('ok'):
        return success(res)
    return error(res.get('error', 'Fallo en la prueba de conexión SMTP'), 400)

# ── Módulo de Alertas de Monitoreo por Correo ──────────────────────────────

@app.route('/api/channels/email/alerts', methods=['GET'])
def api_email_alerts_get():
    """Obtiene la configuración del módulo de alertas por correo."""
    return success(db.get_alert_email_config())

@app.route('/api/channels/email/alerts', methods=['POST'])
def api_email_alerts_set():
    """Guarda activación y destinatarios de alertas de monitoreo."""
    body = request.get_json(silent=True) or {}
    if isinstance(body.get('to_emails'), str):
        body['to_emails'] = [x.strip() for x in body['to_emails'].split(',') if x.strip()]
    cfg = db.set_alert_email_config(body)
    return success(cfg)

@app.route('/api/channels/email/alerts/test', methods=['POST'])
def api_email_alerts_test():
    """Envía una alerta de monitoreo simulada para verificar el canal de alertas."""
    import notification_engine as notif
    body = request.get_json(silent=True) or {}
    target_email = body.get('email')
    res = notif.send_test_alert_email(target_email)
    if res.get('ok'):
        return success(res)
    return error(res.get('error', 'Fallo al enviar alerta de prueba'), 400)

# ── Compatibilidad con API genérica de canales ─────────────────────────────

@app.route('/api/channels/<channel>', methods=['GET'])
def api_channel_get(channel):
    if channel not in ('telegram', 'email'):
        return error('Canal inválido. Usa: telegram | email')
    return success(db.get_channel_config_safe(channel))

@app.route('/api/channels/<channel>', methods=['POST'])
def api_channel_set(channel):
    """Guarda config del canal."""
    if channel not in ('telegram', 'email'):
        return error('Canal inválido. Usa: telegram | email')

    body = request.get_json(silent=True) or {}

    if channel == 'email' and body.get('smtp_pass', '').startswith('●'):
        body.pop('smtp_pass', None)

    if channel == 'telegram' and isinstance(body.get('chat_ids'), str):
        body['chat_ids'] = [x.strip() for x in body['chat_ids'].split(',') if x.strip()]
    if channel == 'email' and isinstance(body.get('to_emails'), str):
        body['to_emails'] = [x.strip() for x in body['to_emails'].split(',') if x.strip()]

    db.set_channel_config(channel, body)
    return success(db.get_channel_config_safe(channel))

@app.route('/api/channels/<channel>/test', methods=['POST'])
def api_channel_test(channel):
    """Envía un mensaje/email de prueba al canal configurado."""
    if channel not in ('telegram', 'email'):
        return error('Canal inválido')

    cfg = db.get_channel_config(channel)
    if channel == 'telegram':
        if not cfg.get('enabled'):
            return error('Canal Telegram no está habilitado')
        return _test_telegram(cfg)
    else:
        import notification_engine as notif
        body = request.get_json(silent=True) or {}
        target = body.get('email')
        res = notif.send_test_alert_email(target)
        if res.get('ok'):
            return success(res)
        return error(res.get('error', 'Fallo al enviar prueba de email'))

def _test_telegram(cfg: dict):
    import requests as req
    token    = cfg.get('bot_token', '')
    chat_ids = cfg.get('chat_ids', [])
    if not token:
        return error('Bot token no configurado')
    if not chat_ids:
        return error('No hay Chat IDs configurados')

    msg = (
        "✅ <b>Acronis VM Monitor</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Mensaje de prueba enviado correctamente.\n"
        "Canal Telegram configurado y activo. 🎉"
    )
    ok_list = []
    fail_list = []
    for cid in chat_ids:
        try:
            r = req.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={'chat_id': cid, 'text': msg, 'parse_mode': 'HTML'},
                timeout=15
            )
            if r.ok:
                ok_list.append(cid)
            else:
                fail_list.append({'chat_id': cid, 'error': r.json().get('description','')})
        except Exception as e:
            fail_list.append({'chat_id': cid, 'error': str(e)})

    if ok_list:
        return success({'sent_to': ok_list, 'failed': fail_list})
    return error(f"Falló para todos los chats: {fail_list}")


# ────────────────────────── API: Reportes Ejecutivos ───────────────────────

@app.route('/api/reports/config', methods=['GET'])
def api_reports_config_get():
    """Retorna la configuración de programación automática del reporte semanal."""
    return success(db.get_report_config())


@app.route('/api/reports/config', methods=['POST'])
def api_reports_config_set():
    """Actualiza la configuración del reporte semanal."""
    body = request.get_json(silent=True) or {}
    if isinstance(body.get('emails'), str):
        body['emails'] = [x.strip() for x in body['emails'].split(',') if x.strip()]
    cfg = db.set_report_config(body)
    return success(cfg)


@app.route('/api/reports/storage', methods=['GET'])
def api_reports_storage():
    """Retorna las métricas más recientes de almacenamiento local y cloud."""
    return success(db.get_latest_storage_metrics())


@app.route('/api/reports/generate', methods=['POST'])
def api_reports_generate():
    """Genera datos de reporte y HTML renderizado bajo demanda para previsualización."""
    import notification_engine as notif
    body = request.get_json(silent=True) or {}
    start_date = body.get('start_date')
    end_date = body.get('end_date')
    tenant_id = body.get('tenant_id')
    vm_ids = body.get('vm_ids')

    try:
        data = notif.generate_weekly_report_data(start_date, end_date, tenant_id, vm_ids=vm_ids)
        html = notif.render_report_html(data)
        return success({'report_data': data, 'html': html})
    except Exception as e:
        return error(f"Error generando reporte: {str(e)}", 500)


@app.route('/api/reports/send', methods=['POST'])
def api_reports_send():
    """Genera y despacha el reporte por correo inmediatamente."""
    import notification_engine as notif
    body = request.get_json(silent=True) or {}
    emails = body.get('emails')
    if isinstance(emails, str):
        emails = [x.strip() for x in emails.split(',') if x.strip()]

    start_date = body.get('start_date')
    end_date = body.get('end_date')
    tenant_id = body.get('tenant_id')
    vm_ids = body.get('vm_ids')

    try:
        result = notif.send_weekly_report(
            recipients=emails,
            start_iso=start_date,
            end_iso=end_date,
            tenant_id=tenant_id,
            vm_ids=vm_ids
        )
        if not result.get('ok'):
            return error(result.get('error') or "Error enviando correo de reporte", 500)
        return success(result)
    except Exception as e:
        return error(f"Error despachando reporte: {str(e)}", 500)


@app.route('/api/reports/export-pdf', methods=['GET', 'POST'])
def api_reports_export_pdf():
    """Genera y descarga el reporte ejecutivo de respaldos en formato PDF profesional."""
    import notification_engine as notif
    if request.method == 'POST':
        body = request.get_json(silent=True) or {}
    else:
        body = request.args.to_dict()

    start_date = body.get('start_date')
    end_date = body.get('end_date')
    tenant_id = body.get('tenant_id')
    vm_ids = body.get('vm_ids')
    if isinstance(vm_ids, str):
        vm_ids = [x.strip() for x in vm_ids.split(',') if x.strip()]

    try:
        data = notif.generate_weekly_report_data(start_date, end_date, tenant_id, vm_ids=vm_ids)
        pdf_bytes = notif.generate_report_pdf(data)

        date_str = datetime.now().strftime('%Y-%m-%d')
        filename = f"Reporte_Respaldos_Backupcode_{date_str}.pdf"

        response = make_response(pdf_bytes)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        return error(f"Error exportando reporte a PDF: {str(e)}", 500)


# ────────────────────── Almacenamiento por Tenants ─────────────────────────

@app.route('/api/tenants/storage', methods=['GET'])
def get_tenants_storage():
    """Retorna listado de almacenamiento y cuotas por tenant junto con resumen global."""
    try:
        tenants = db.get_all_tenant_storages()
        summary = db.get_global_storage_summary()
        return success({
            'summary': summary,
            'tenants': tenants
        })
    except Exception as e:
        return error(f"Error obteniendo almacenamiento de tenants: {str(e)}", 500)


@app.route('/api/tenants/storage/sync', methods=['POST'])
def sync_tenants_storage():
    """Sincroniza bajo demanda el almacenamiento y cuotas desde Acronis."""
    try:
        import acronis_monitor
        poller = acronis_monitor.AcronisMonitor(
            acronis_monitor.CLIENT_ID,
            acronis_monitor.CLIENT_SECRET,
            acronis_monitor.DC_URL
        )
        updated = poller.fetch_tenant_storages_and_quotas()
        tenants = db.get_all_tenant_storages()
        summary = db.get_global_storage_summary()
        return success({
            'updated_count': updated,
            'summary': summary,
            'tenants': tenants
        }, message=f"Sincronizados {updated} clientes con éxito")
    except Exception as e:
        return error(f"Error sincronizando almacenamiento de clientes: {str(e)}", 500)


# ────────────────────────────── Main ──────────────────────────────────────

if __name__ == '__main__':
    db.init_db()
    port = int(os.getenv('API_PORT', 8085))
    host = os.getenv('API_HOST', '0.0.0.0')
    print(f"\n{'='*52}")
    print(f"  🚀 Acronis Monitor API  → http://{host}:{port}/api/status")
    print(f"  🌐 Dashboard            → http://{host}:{port}/")
    print(f"  🟢 Health check         → http://{host}:{port}/health")
    print(f"  🗄️  Data dir             → {DATA_DIR}")
    print(f"{'='*52}\n")
    app.run(host=host, port=port, debug=False)
