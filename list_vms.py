import requests
import os
import json
from base64 import b64encode
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv('ACRONIS_CLIENT_ID')
CLIENT_SECRET = os.getenv('ACRONIS_CLIENT_SECRET')
DC_URL = os.getenv('ACRONIS_DC_URL', 'https://us5-cloud.acronis.com').rstrip('/')

def get_token():
    auth_str = f"{CLIENT_ID}:{CLIENT_SECRET}"
    encoded_auth = b64encode(auth_str.encode()).decode()
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {encoded_auth}'
    }
    data = {'grant_type': 'client_credentials'}
    response = requests.post(f"{DC_URL}/api/2/idp/token", headers=headers, data=data)
    response.raise_for_status()
    return response.json().get('access_token')

def list_all_vms():
    token = get_token()
    headers = {'Authorization': f'Bearer {token}'}
    params = {'type': 'resource.machine'}
    
    url = f"{DC_URL}/api/resource_management/v4/resource_statuses"
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    
    items = response.json().get('items', [])
    print(f"\n{'#'*60}")
    print(f"{'ID de la VM':<40} | {'Nombre de la VM'}")
    print(f"{'-'*40} | {'-'*20}")
    
    for item in items:
        vm_id = item.get('context', {}).get('id')
        name = item.get('context', {}).get('name')
        print(f"{vm_id:<40} | {name}")
    print(f"{'#'*60}\n")
    print("Copia los IDs que desees monitorear y agrégalos a tu archivo .env en la variable SELECTED_VM_IDS separados por comas.")

if __name__ == "__main__":
    if not CLIENT_ID or not CLIENT_SECRET:
        print("Configura las credenciales en el archivo .env primero.")
    else:
        try:
            list_all_vms()
        except Exception as e:
            print(f"Error: {e}")
