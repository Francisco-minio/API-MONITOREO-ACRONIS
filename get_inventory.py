import requests
import json
import os
from base64 import b64encode
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv('ACRONIS_CLIENT_ID')
CLIENT_SECRET = os.getenv('ACRONIS_CLIENT_SECRET')
DC_URL = os.getenv('ACRONIS_DC_URL', 'https://us5-cloud.acronis.com').rstrip('/')

class AcronisInventory:
    def __init__(self, client_id, client_secret, dc_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.dc_url = dc_url
        self.token = None

    def get_token(self):
        auth_str = f"{self.client_id}:{self.client_secret}"
        encoded_auth = b64encode(auth_str.encode()).decode()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {encoded_auth}'
        }
        data = {'grant_type': 'client_credentials'}
        response = requests.post(f"{self.dc_url}/api/2/idp/token", headers=headers, data=data)
        response.raise_for_status()
        self.token = response.json().get('access_token')
        return self.token

    def get_resources(self):
        headers = {'Authorization': f'Bearer {self.token}'}
        all_items = []
        cursor = None
        
        while True:
            params = {
                'include_attributes': 'true',
                'type': 'resource.machine',
                'limit': 100
            }
            if cursor:
                params['after'] = cursor
                
            response = requests.get(f"{self.dc_url}/api/resource_management/v4/resource_statuses", headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            items = data.get('items', [])
            all_items.extend(items)
            
            paging = data.get('paging', {})
            cursor = paging.get('cursors', {}).get('after')
            if not cursor or not items:
                break
                
        return all_items

    def build_inventory(self):
        print("Obteniendo inventario completo agrupado por cliente...")
        self.get_token()
        resources = self.get_resources()
        print(f"Total estaciones/servidores encontrados: {len(resources)}")
        
        inventory = {}
        
        for res in resources:
            context = res.get('context', {})
            t_id = context.get('tenant_id')
            t_name = context.get('tenant_name') or f"Cliente {t_id}"
            
            if t_id not in inventory:
                inventory[t_id] = {
                    "cliente_nombre": t_name,
                    "estaciones_y_servidores": []
                }
            
            # Clasificar por tipo si es posible (simplificado)
            # Generalmente 'resource.machine' incluye ambos.
            
            raw_plans = res.get('aggregate', {}).get('names', [])
            plan_names = []
            if isinstance(raw_plans, str):
                plan_names = [raw_plans]
            elif isinstance(raw_plans, list):
                plan_names = raw_plans
            
            item_data = {
                "id": context.get('id'),
                "nombre": context.get('name'),
                "version_agente": res.get('attributes', {}).get('agent_version', 'N/A'),
                "planes_asociados": plan_names,
                "estado_proteccion": res.get('aggregate', {}).get('status', 'unknown')
            }
            
            inventory[t_id]["estaciones_y_servidores"].append(item_data)
            
        return inventory

if __name__ == "__main__":
    inv_tool = AcronisInventory(CLIENT_ID, CLIENT_SECRET, DC_URL)
    try:
        data = inv_tool.build_inventory()
        with open('acronis_full_inventory.json', 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Inventario generado exitosamente en 'acronis_full_inventory.json' ({len(data)} clientes).")
    except Exception as e:
        print(f"Error generando inventario: {e}")
