"""
acronis_monitor.py  (v2 - con SQLite + detección de cambios)

Flujo de trabajo:
  1. Cada POLLING_INTERVAL segundos consulta la API de Acronis.
  2. Normaliza cada VM y la pasa a acronis_db.upsert_machine().
  3. upsert_machine() detecta los cambios y los guarda en la tabla history.
  4. Si hay cambios críticos se puede enviar notification (extensible).
  5. El api_server.py sirve los datos al Dashboard directamente desde la DB.
"""

import requests
import json
import time
import os
import sys
from datetime import datetime, timezone, timedelta
from base64 import b64encode
from dotenv import load_dotenv

# Importar capa de DB
sys.path.insert(0, os.path.dirname(__file__))
import acronis_db as db

load_dotenv()

# ─────────────── Configuración ─────────────────────────────────────────────
CLIENT_ID          = os.getenv('ACRONIS_CLIENT_ID')
CLIENT_SECRET      = os.getenv('ACRONIS_CLIENT_SECRET')
DC_URL             = os.getenv('ACRONIS_DC_URL', 'https://us5-cloud.acronis.com').rstrip('/')
INTERVAL           = int(os.getenv('POLLING_INTERVAL_SECONDS', 300))
CYBERFIT_THRESHOLD = int(os.getenv('CYBERFIT_THRESHOLD', 500))
# Directorio de datos compartido (útil en Docker con volumen montado)
DATA_DIR           = os.getenv('DATA_DIR', os.path.dirname(os.path.abspath(__file__)))
os.makedirs(DATA_DIR, exist_ok=True)
MONITOR_JSON       = os.path.join(DATA_DIR, 'monitor_status.json')
# IDs opcionales para monitorear solo ciertos equipos (vacío = todos)
SELECTED_VM_IDS    = [x.strip() for x in os.getenv('SELECTED_VM_IDS', '').split(',') if x.strip()]


# ─────────────── Clase principal ───────────────────────────────────────────

class AcronisMonitor:
    def __init__(self, client_id, client_secret, dc_url):
        self.client_id     = client_id
        self.client_secret = client_secret
        self.dc_url        = dc_url
        self.token         = None
        self.token_expires = 0   # timestamp UNIX

    # ── Autenticación ──────────────────────────────────────────────────────

    def get_token(self):
        print("[AUTH] Autenticando con Acronis...")
        auth_str     = f"{self.client_id}:{self.client_secret}"
        encoded_auth = b64encode(auth_str.encode()).decode()

        headers = {
            'Content-Type':  'application/x-www-form-urlencoded',
            'Authorization': f'Basic {encoded_auth}'
        }
        response = requests.post(
            f"{self.dc_url}/api/2/idp/token",
            headers=headers,
            data={'grant_type': 'client_credentials'},
            timeout=30
        )
        response.raise_for_status()
        payload          = response.json()
        self.token       = payload.get('access_token')
        # Renovar 60 seg antes del vencimiento
        self.token_expires = time.time() + payload.get('expires_in', 3600) - 60
        print("[AUTH] Autenticación exitosa.")

    def ensure_token(self):
        if not self.token or time.time() >= self.token_expires:
            self.get_token()

    # ── Fetch API ──────────────────────────────────────────────────────────

    def fetch_resource_statuses(self) -> list:
        self.ensure_token()
        headers   = {'Authorization': f'Bearer {self.token}'}
        all_items = []
        cursor    = None
        page      = 0

        while True:
            params = {
                'include_attributes': 'true',
                'limit':              100
            }
            if cursor:
                params['after'] = cursor

            response = requests.get(
                f"{self.dc_url}/api/resource_management/v4/resource_statuses",
                headers=headers,
                params=params,
                timeout=60
            )

            if response.status_code == 401:
                self.get_token()
                headers  = {'Authorization': f'Bearer {self.token}'}
                response = requests.get(
                    f"{self.dc_url}/api/resource_management/v4/resource_statuses",
                    headers=headers,
                    params=params,
                    timeout=60
                )

            response.raise_for_status()
            data  = response.json()
            items = data.get('items', [])
            all_items.extend(items)
            page += 1

            paging = data.get('paging', {})
            cursor = paging.get('cursors', {}).get('after')
            if not cursor or not items:
                break

            print(f"  [API] Página {page} → {len(all_items)} recursos hasta ahora...")

        return all_items

    # ── Normalización ──────────────────────────────────────────────────────

    @staticmethod
    def parse_iso(iso_str):
        """Parsea fechas ISO con nanosegundos (tolerante a variaciones)."""
        if not iso_str:
            return None
        try:
            if '.' in iso_str:
                parts     = iso_str.split('.')
                time_part = parts[0]
                tail      = parts[1]
                if '+' in tail:
                    tz_parts  = tail.split('+')
                    nano_part = tz_parts[0][:6]
                    return datetime.fromisoformat(f"{time_part}.{nano_part}+{tz_parts[1]}")
                elif 'Z' in tail:
                    nano_part = tail.split('Z')[0][:6]
                    return datetime.fromisoformat(f"{time_part}.{nano_part}+00:00")
            return datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        except Exception:
            return None

    def normalize_vm(self, item: dict) -> dict:
        context    = item.get('context', {})
        aggregate  = item.get('aggregate', {})
        policies   = item.get('policies', [])
        attributes = item.get('attributes', {})

        # Plan de backup
        backup_policy = next((p for p in policies if 'backup' in p.get('type', '')), {})
        am_policy     = next((p for p in policies if 'antimalware' in p.get('type', '').lower()
                              or 'alert.malware' in p.get('type', '').lower()), {})

        raw_names  = aggregate.get('names', [])
        plan_name  = (raw_names[0] if isinstance(raw_names, list) and raw_names
                      else (raw_names if isinstance(raw_names, str) else "Sin Plan"))

        vm = {
            "vm_id":                context.get('id'),
            "name":                 context.get('name'),
            "tenant_id":            context.get('tenant_id'),
            "tenant_name":          context.get('tenant_name') or f"Cliente {context.get('tenant_id')}",
            "agent_version":        attributes.get('agent_version', 'Unknown'),
            "protection_plan":      plan_name,
            "protection_status":    aggregate.get('status', 'unknown'),
            "cyberfit_score":       attributes.get('cyberfit_score', 0) or 0,
            "last_backup_success":  backup_policy.get('last_success_run'),
            "next_backup":          backup_policy.get('next_run'),
            "backup_size_gb":       attributes.get('last_backup_size_gb', 0) or 0,
            "last_antimalware_scan": am_policy.get('last_success_run'),
            "next_antimalware_scan": am_policy.get('next_run'),
        }

        # ── Reglas de alerta ───────────────────────────────────────────────
        alerts = []
        now    = datetime.now(timezone.utc)

        if vm['protection_status'] in ('critical', 'warning'):
            alerts.append(f"CRITICAL: Estado de protección es {vm['protection_status'].upper()}")

        last_backup = self.parse_iso(vm['last_backup_success'])
        if last_backup:
            if now - last_backup > timedelta(hours=25):
                hours_ago = int((now - last_backup).total_seconds() / 3600)
                alerts.append(f"WARNING: Último backup hace {hours_ago}h (>25h)")
        else:
            alerts.append("WARNING: No hay registros de backup exitoso")

        next_backup = self.parse_iso(vm['next_backup'])
        if next_backup and now > next_backup:
            alerts.append("WARNING: Backup programado está vencido")

        score = vm['cyberfit_score']
        if isinstance(score, (int, float)) and score < CYBERFIT_THRESHOLD:
            alerts.append(f"WARNING: CyberFit Score bajo ({score}/{CYBERFIT_THRESHOLD})")

        next_scan = self.parse_iso(vm['next_antimalware_scan'])
        if next_scan and now > next_scan:
            alerts.append("WARNING: Escaneo antimalware vencido")

        vm['alerts'] = alerts
        return vm

    # ── Ciclo principal ────────────────────────────────────────────────────

    def run(self):
        db.init_db()
        cycle = 0
        print(f"\n{'='*60}")
        print(f"  Acronis Monitor v2  |  Intervalo: {INTERVAL}s")
        print(f"  Filtro activo: {len(SELECTED_VM_IDS)} IDs  |  Umbral CyberFit: {CYBERFIT_THRESHOLD}")
        print(f"{'='*60}\n")

        while True:
            cycle += 1
            try:
                print(f"\n[CICLO {cycle}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

                # 1. Obtener datos de la API
                items = self.fetch_resource_statuses()
                print(f"[API] Total recursos recibidos: {len(items)}")

                # 2. Filtrar si hay selección manual
                if SELECTED_VM_IDS:
                    items = [i for i in items if i.get('context', {}).get('id') in SELECTED_VM_IDS]
                    print(f"[FILTRO] {len(items)} equipos seleccionados")

                # 3. Normalizar y guardar en DB (detecta cambios automáticamente)
                total_changes = 0
                now_iso       = datetime.now(timezone.utc).isoformat()

                for item in items:
                    vm      = self.normalize_vm(item)
                    changes = db.upsert_machine(vm, now_iso)
                    if changes:
                        total_changes += len(changes)
                        for c in changes:
                            sev_icon = "🔴" if c['severity'] == 'critical' else ("🟡" if c['severity'] == 'warning' else "🟢")
                            print(f"  {sev_icon} [{c['vm_name']}] {c['field_changed']}: "
                                  f"{c['old_value']} → {c['new_value']}")

                print(f"[DB] {len(items)} VMs procesadas | {total_changes} cambios registrados")

                # 4. Guardar también el JSON para compatibilidad con frontend legacy
                all_machines = db.get_all_machines()
                with open(MONITOR_JSON, 'w') as f:
                    json.dump(all_machines, f, indent=2)

                print(f"[OK] Ciclo completado. Próximo en {INTERVAL}s...")

            except requests.exceptions.RequestException as e:
                print(f"[ERROR RED] {e}")
            except Exception as e:
                import traceback
                print(f"[ERROR] {e}")
                traceback.print_exc()

            time.sleep(INTERVAL)


# ─────────────── Punto de entrada ──────────────────────────────────────────

if __name__ == '__main__':
    if not CLIENT_ID or not CLIENT_SECRET:
        print("❌  Configura ACRONIS_CLIENT_ID y ACRONIS_CLIENT_SECRET en el archivo .env")
        sys.exit(1)

    monitor = AcronisMonitor(CLIENT_ID, CLIENT_SECRET, DC_URL)
    monitor.run()
