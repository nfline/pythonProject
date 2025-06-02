import logging
import requests
import pandas as pd
import keyring
import getpass
import os

APP_NAME = "keyring"
KEY_NAME = "keyring"
BASE_URL_TEMPLATE = "https://api.appsec.fortinet.com/v2/waf/apps/{}/servers"

logging.basicConfig(filename='update_server.log', level=logging.DEBUG,
                   format='%(asctime)s - %(levelname)s - %(message)s')

def get_api_key():
    api_key = keyring.get_password(APP_NAME, KEY_NAME)
    if not api_key:
        api_key = getpass.getpass("Enter API Key: ").strip()
        keyring.set_password(APP_NAME, KEY_NAME, api_key)
    return api_key

def create_session():
    session = requests.Session()
    session.headers.update({
        'Authorization': f'Basic {get_api_key()}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    })
    session.verify = False
    return session

def update_server_pool(session, ep_id: str, origin_ip: str, backup_ip: str):
    formatted_ep_id = str(ep_id).zfill(10)
    url = BASE_URL_TEMPLATE.format(formatted_ep_id)
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        config = response.json().get('result', {})

        server_pools = config.get("server_pools", [])
        if not server_pools:
            logging.warning(f"No server pools found for {ep_id}")
            return

        pool = server_pools[0]
        existing_servers = pool.setdefault("server_list", [])

        # Add origin if missing
        if origin_ip and not any(s.get("addr") == origin_ip for s in existing_servers):
            existing_servers.append({
                "addr": origin_ip,
                "port": 80,
                "backup": False,
                "enabled": True
            })

        # Add backup if missing
        if backup_ip and not any(s.get("addr") == backup_ip for s in existing_servers):
            existing_servers.append({
                "addr": backup_ip,
                "port": 80,
                "backup": True,
                "enabled": True
            })

        # Enable health check
        pool.setdefault("health", {})["health_check"] = True

        # Send update
        update_response = session.put(url, json={"server_pools": server_pools})
        update_response.raise_for_status()
        logging.info(f"Updated {ep_id} with origin ({origin_ip}) and backup ({backup_ip})")
        print(f"Updated {ep_id}")

    except Exception as e:
        logging.error(f"Failed to update {ep_id}: {str(e)}")
        print(f"Failed to update {ep_id}: {str(e)}")

def main():
    input_file = "update_ips.xlsx"
    if not os.path.exists(input_file):
        print(f"Input file '{input_file}' not found.")

    df = pd.read_excel(input_file)
    if not {"ep_id", "origin_ip", "backup_ip"}.issubset(df.columns):
        print("Input file must contain 'ep_id', 'origin_ip', and 'backup_ip' columns.")
        return

    session = create_session()
    for _, row in df.iterrows():
        ep_id = row['ep_id']
        origin_ip = row['origin_ip']
        backup_ip = row['backup_ip']
        update_server_pool(session, ep_id, origin_ip, backup_ip)

if __name__ == "__main__":
    main() 
