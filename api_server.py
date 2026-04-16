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
from datetime import datetime, timezone
from flask import Flask, jsonify, request, send_from_directory, abort
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
    return jsonify({'ok': True, 'data': data, **kwargs})

def error(msg, code=400):
    return jsonify({'ok': False, 'error': msg}), code

# ────────────────────────── Rutas estáticas ────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(APP_DIR, 'index.html')

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
    """Devuelve config (sin contraseñas) de todos los canales."""
    return success({
        'telegram': db.get_channel_config_safe('telegram'),
        'email':    db.get_channel_config_safe('email'),
    })

@app.route('/api/channels/<channel>', methods=['GET'])
def api_channel_get(channel):
    if channel not in ('telegram', 'email'):
        return error('Canal inválido. Usa: telegram | email')
    return success(db.get_channel_config_safe(channel))

@app.route('/api/channels/<channel>', methods=['POST'])
def api_channel_set(channel):
    """Guarda config del canal. La contraseña solo se actualiza si se envía
    un valor real (no el placeholder ●●●●●●)."""
    if channel not in ('telegram', 'email'):
        return error('Canal inválido. Usa: telegram | email')

    body = request.get_json(silent=True) or {}

    # Si el frontend no cambió la contraseña, no sobreescribir
    if channel == 'email' and body.get('smtp_pass', '').startswith('●'):
        body.pop('smtp_pass', None)

    # chat_ids y to_emails pueden venir como string separado por comas
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
    if not cfg.get('enabled'):
        return error(f'Canal {channel} no está habilitado')

    if channel == 'telegram':
        return _test_telegram(cfg)
    else:
        return _test_email(cfg)

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

def _test_email(cfg: dict):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    host       = cfg.get('smtp_host','')
    port       = int(cfg.get('smtp_port', 587))
    user       = cfg.get('smtp_user','')
    pwd        = cfg.get('smtp_pass','')
    from_addr  = cfg.get('from_email','') or user
    to_addrs   = cfg.get('to_emails', [])
    use_tls    = cfg.get('use_tls', True)

    if not host:
        return error('SMTP host no configurado')
    if not to_addrs:
        return error('No hay destinatarios configurados')

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = '✅ Acronis VM Monitor – Mensaje de prueba'
        msg['From']    = from_addr
        msg['To']      = ', '.join(to_addrs)
        html = """
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;
                    background:#0f172a;color:#f1f5f9;padding:24px;border-radius:12px;">
          <h2 style="color:#60a5fa">✅ Acronis VM Monitor</h2>
          <hr style="border-color:#1e293b">
          <p>Mensaje de prueba enviado correctamente.</p>
          <p style="color:#64748b">Canal Email SMTP configurado y activo. 🎉</p>
        </div>"""
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(host, port, timeout=15) as srv:
            if use_tls:
                srv.starttls()
            if user and pwd:
                srv.login(user, pwd)
            srv.sendmail(from_addr, to_addrs, msg.as_string())

        return success({'sent_to': to_addrs})
    except Exception as e:
        return error(f'Error SMTP: {str(e)}')

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
