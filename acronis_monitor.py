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
from base64 import b64encode, b64decode
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

    # ── Task Manager / Activities (Histórico de respaldos) ─────────────────

    def fetch_activities(self) -> int:
        """Consulta Task Manager API v2 para obtener actividades recientes de backup."""
        self.ensure_token()
        headers = {'Authorization': f'Bearer {self.token}'}
        inserted = 0
        try:
            params = {
                'limit': 200,
                'order': 'desc(createdAt)'
            }
            response = requests.get(
                f"{self.dc_url}/api/task_manager/v2/activities",
                headers=headers,
                params=params,
                timeout=45
            )
            if response.status_code == 401:
                self.get_token()
                headers = {'Authorization': f'Bearer {self.token}'}
                response = requests.get(
                    f"{self.dc_url}/api/task_manager/v2/activities",
                    headers=headers,
                    params=params,
                    timeout=45
                )

            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                for item in items:
                    pol = item.get('policy') or {}
                    ctx = item.get('context') or {}
                    res = item.get('resource') or {}
                    prog = item.get('progress') or {}
                    runtime = ctx.get('_runtime') or {}

                    is_backup = (
                        pol.get('type') == 'backup' or
                        'BackupPlanName' in ctx or
                        'backup' in str(ctx.get('title', '')).lower() or
                        'backup' in str(item.get('type', '')).lower()
                    )
                    if not is_backup:
                        continue

                    state = (item.get('state') or item.get('status') or '').lower()
                    result_obj = item.get('result') or {}
                    result_code = result_obj.get('code', '') if isinstance(result_obj, dict) else ''

                    if state in ('failed', 'error') or result_code in ('error', 'failed'):
                        res_val = 'failed'
                    elif state in ('warning', 'completed_with_warnings') or result_code == 'warning':
                        res_val = 'warning'
                    elif state in ('completed', 'success') or result_code == 'ok':
                        res_val = 'success'
                    else:
                        res_val = 'success'

                    err_msg = None
                    if res_val in ('failed', 'warning'):
                        if isinstance(result_obj, dict):
                            err_info = result_obj.get('error', {})
                            if isinstance(err_info, dict):
                                err_msg = err_info.get('details', {}).get('info') or err_info.get('message')
                            elif isinstance(err_info, str):
                                err_msg = err_info
                        if not err_msg:
                            err_msg = str(result_obj.get('payload') or state)

                    start_t = item.get('startedAt') or item.get('createdAt') or item.get('started_at')
                    end_t = item.get('completedAt') or item.get('completed_at') or start_t

                    dur = 0
                    if start_t and end_t:
                        try:
                            t0 = datetime.fromisoformat(start_t.replace('Z', '+00:00'))
                            t1 = datetime.fromisoformat(end_t.replace('Z', '+00:00'))
                            dur = max(0, int((t1 - t0).total_seconds()))
                        except Exception:
                            dur = item.get('duration') or 0

                    size_b = prog.get('bytesSaved') or prog.get('bytesProcessed') or runtime.get('bytesSaved') or runtime.get('bytesProcessed') or 0

                    vm_id = res.get('id') or ctx.get('resource_id') or ctx.get('id')
                    vm_name = res.get('name') or ctx.get('MachineName') or ctx.get('resource_name')
                    tenant = item.get('tenant') or {}
                    tenant_id = tenant.get('id') or item.get('tenant_id') or ctx.get('tenant_id')
                    tenant_name = tenant.get('name') or ctx.get('tenant_name')
                    plan_lower = plan_name.lower()
                    if any(k in plan_lower for k in ('[local]', 'local', 'ntfs', 'smb', 'disco local', 'carpeta local')):
                        st_target = 'local_ntfs'
                    else:
                        st_target = 'cloud_acronis'

                    rec = {
                        'activity_id': str(item.get('uuid') or item.get('id')),
                        'vm_id': vm_id,
                        'vm_name': vm_name,
                        'tenant_id': tenant_id,
                        'tenant_name': tenant_name,
                        'plan_name': plan_name,
                        'start_time': start_t,
                        'end_time': end_t,
                        'duration_seconds': int(dur),
                        'result': res_val,
                        'error_message': str(err_msg) if err_msg else None,
                        'size_bytes': int(size_b),
                        'storage_target': st_target,
                        'created_at': end_t or datetime.now(timezone.utc).isoformat()
                    }
                    if db.insert_backup_execution(rec):
                        inserted += 1

                    # Si obtuvimos un tamaño mayor a 0, actualizar máquinas si coincide el nombre
                    if size_b > 0 and vm_name:
                        size_gb = round(size_b / (1024**3), 2)
                        with db.get_conn() as conn:
                            conn.execute(
                                "UPDATE machines SET backup_size_gb = ? WHERE (name = ? OR name LIKE ?) AND (backup_size_gb IS NULL OR backup_size_gb = 0)",
                                (size_gb, vm_name, f"{vm_name}%")
                            )

            elif response.status_code == 404:
                pass
        except Exception as e:
            print(f"  [ACTIVITIES ERROR] {e}")

        return inserted

    # ── Agent Versions ─────────────────────────────────────────────────────

    def fetch_agent_versions(self) -> int:
        """Consulta Agent Manager API v2 para actualizar versiones reales de agente."""
        self.ensure_token()
        headers = {'Authorization': f'Bearer {self.token}'}
        updated = 0
        try:
            r = requests.get(f"{self.dc_url}/api/agent_manager/v2/agents", headers=headers, params={'limit': 100}, timeout=45)
            if r.status_code == 200:
                agents = r.json().get('items', [])
                with db.get_conn() as conn:
                    for ag in agents:
                        h = ag.get('hostname')
                        ver_obj = ag.get('installer_version', {}).get('current', {}) or ag.get('core_version', {}).get('current', {})
                        rel = ver_obj.get('release_id')
                        build = ver_obj.get('build')
                        if rel and h:
                            ver_str = f"v{rel} ({build})" if build else f"v{rel}"
                            cur = conn.execute(
                                "UPDATE machines SET agent_version = ? WHERE name = ? OR name LIKE ?",
                                (ver_str, h, f"{h}%")
                            )
                            updated += cur.rowcount
        except Exception as e:
            print(f"  [AGENT VERSION ERROR] {e}")
        return updated

    # ── Almacenamiento Local (NTFS/Vaults) & Cloud ──────────────────────────

    def fetch_storage_and_usages(self) -> int:
        """Consulta capacidades de almacenamiento local (Vaults/NTFS) y Cloud."""
        self.ensure_token()
        headers = {'Authorization': f'Bearer {self.token}'}
        recorded = 0
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Consultar Vaults locales / NTFS (/api/vault_manager/v1/vaults)
        try:
            r = requests.get(f"{self.dc_url}/api/vault_manager/v1/vaults", headers=headers, timeout=30)
            if r.status_code == 200:
                vaults = r.json().get('items', [])
                for v in vaults:
                    v_name = v.get('name') or v.get('id', 'Almacenamiento Local NTFS')
                    v_type = 'local_ntfs' if v.get('type') in ('local', 'smb', 'nfs', 'directory') else 'cloud_acronis'
                    total = v.get('total_space', 0) or 0
                    free = v.get('free_space', 0) or 0
                    used = max(0, total - free) if total > 0 else (v.get('used_space', 0) or 0)
                    pct = round((used / total * 100.0), 1) if total > 0 else 0.0

                    db.insert_storage_snapshot({
                        'tenant_id': v.get('tenant_id'),
                        'tenant_name': v.get('tenant_name') or 'Infraestructura Local',
                        'storage_name': v_name,
                        'storage_type': v_type,
                        'total_bytes': total,
                        'used_bytes': used,
                        'free_bytes': free,
                        'usage_percent': pct,
                        'timestamp': now_iso
                    })
                    recorded += 1
        except Exception:
            pass

        # 2. Consultar Usages de Tenants (/api/2/tenants/usages) para Cloud Storage
        try:
            r_use = requests.get(f"{self.dc_url}/api/2/tenants/usages", headers=headers, timeout=30)
            if r_use.status_code == 200:
                usage_items = r_use.json().get('items', [])
                for u in usage_items:
                    name = u.get('name', '')
                    if 'cloud_storage' in name or 'storage' in name:
                        used = u.get('usage', 0) or 0
                        quota = u.get('quota', {}).get('value') if isinstance(u.get('quota'), dict) else 0
                        quota = quota or 0
                        free = max(0, quota - used) if quota > 0 else 0
                        pct = round((used / quota * 100.0), 1) if quota > 0 else 0.0

                        db.insert_storage_snapshot({
                            'tenant_id': u.get('tenant_id'),
                            'tenant_name': u.get('tenant_name') or f"Cliente {u.get('tenant_id')}",
                            'storage_name': f"Acronis Cloud Storage",
                            'storage_type': 'cloud_acronis',
                            'total_bytes': quota,
                            'used_bytes': used,
                            'free_bytes': free,
                            'usage_percent': pct,
                            'timestamp': now_iso
                        })
                        recorded += 1
        except Exception:
            pass

        return recorded

    # ── Almacenamiento & Cuotas por Tenant/Cliente ──────────────────────────

    def fetch_tenant_storages_and_quotas(self) -> int:
        """Consulta almacenamiento y cuotas de cada cliente/tenant en Acronis."""
        self.ensure_token()
        headers = {'Authorization': f'Bearer {self.token}'}
        updated = 0
        try:
            parts = self.token.split('.')
            if len(parts) < 2:
                return 0
            payload = json.loads(b64decode(parts[1] + '==').decode('utf-8'))
            owner_tuid = payload.get('owner_tuid')
            if not owner_tuid:
                return 0

            r = requests.get(
                f"{self.dc_url}/api/2/tenants",
                headers=headers,
                params={'subtree_root_id': owner_tuid, 'limit': 100},
                timeout=45
            )
            if r.status_code != 200:
                return 0

            tenants = r.json().get('items', [])
            now_iso = datetime.now(timezone.utc).isoformat()

            for t in tenants:
                tid = t.get('id')
                tname = t.get('name')
                kind = t.get('kind', 'customer')

                # 1. Usages
                r_u = requests.get(f"{self.dc_url}/api/2/tenants/{tid}/usages", headers=headers, timeout=20)
                tot = 0
                loc = 0
                vm = 0
                srv = 0
                ws = 0
                m365 = 0

                if r_u.status_code == 200:
                    for u in r_u.json().get('items', []):
                        name = u.get('name', '')
                        val = u.get('value', 0) or 0
                        if name in ('total_storage', 'storage_total'):
                            tot = max(tot, val)
                        elif name == 'local_storage':
                            loc = val
                        elif name == 'vm_storage':
                            vm = val
                        elif name == 'server_storage':
                            srv = val
                        elif name == 'workstation_storage':
                            ws = val
                        elif name in ('onedrive_storage', 'o365_teams_storage'):
                            m365 += val

                # 2. Offering items para cuota
                r_off = requests.get(f"{self.dc_url}/api/2/tenants/{tid}/offering_items", headers=headers, timeout=20)
                quota = None
                if r_off.status_code == 200:
                    for it in r_off.json().get('items', []):
                        if it.get('name') in ('total_storage', 'storage_total') and isinstance(it.get('quota'), dict):
                            q_val = it.get('quota', {}).get('value')
                            if q_val:
                                quota = q_val

                cld = max(0, tot - loc)
                pct = round((tot / quota * 100.0), 1) if quota else 0.0

                record = {
                    'tenant_id': tid,
                    'tenant_name': tname,
                    'kind': kind,
                    'total_bytes': tot,
                    'local_bytes': loc,
                    'cloud_bytes': cld,
                    'vm_bytes': vm,
                    'server_bytes': srv,
                    'workstation_bytes': ws,
                    'm365_bytes': m365,
                    'quota_bytes': quota,
                    'usage_percent': pct,
                    'updated_at': now_iso
                }
                if db.upsert_tenant_storage(record):
                    updated += 1

        except Exception as e:
            print(f"  [TENANT STORAGE ERROR] {e}")

        return updated

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

                    # Asegurar registro base para el reporte histórico
                    if vm.get('last_backup_success'):
                        p_lower = (vm.get('protection_plan') or '').lower()
                        st_target = 'local_ntfs' if any(k in p_lower for k in ('[local]', 'local', 'ntfs', 'smb')) else 'cloud_acronis'
                        db.insert_backup_execution({
                            'activity_id': f"base_{vm['vm_id']}_{vm['last_backup_success']}",
                            'vm_id': vm['vm_id'],
                            'vm_name': vm.get('name'),
                            'tenant_id': vm.get('tenant_id'),
                            'tenant_name': vm.get('tenant_name'),
                            'plan_name': vm.get('protection_plan'),
                            'start_time': vm.get('last_backup_success'),
                            'end_time': vm.get('last_backup_success'),
                            'result': 'success' if vm.get('protection_status') != 'critical' else 'warning',
                            'size_bytes': int((vm.get('backup_size_gb') or 0) * (1024**3)),
                            'storage_target': st_target,
                            'created_at': vm.get('last_backup_success')
                        })

                print(f"[DB] {len(items)} VMs procesadas | {total_changes} cambios registrados")

                # 4. Obtener actividades de Task Manager (historial de respaldos)
                new_activities = self.fetch_activities()
                if new_activities:
                    print(f"[ACTIVITIES] {new_activities} nuevas ejecuciones de backup registradas")

                # 5. Obtener capacidades de almacenamiento local y cloud
                new_storages = self.fetch_storage_and_usages()
                if new_storages:
                    print(f"[STORAGE] {new_storages} registros de almacenamiento actualizados")

                # 6. Actualizar versiones reales de agente
                updated_agents = self.fetch_agent_versions()
                if updated_agents:
                    print(f"[AGENTS] {updated_agents} versiones de agentes actualizadas")

                # 7. Obtener almacenamiento y cuotas por Tenant/Cliente
                updated_tenants = self.fetch_tenant_storages_and_quotas()
                if updated_tenants:
                    print(f"[TENANTS] {updated_tenants} clientes con almacenamiento y cuotas actualizados")

                # 6. Guardar también el JSON para compatibilidad con frontend legacy
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
