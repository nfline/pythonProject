import logging
import requests
import pandas as pd
import keyring
import getpass
import os
import warnings

# Disable SSL warnings for dev environment
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

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

def clean_server_pools(server_pools):
    """Clean server pools data to handle NaN values for JSON compliance"""
    def clean_value(value):
        if pd.isna(value):
            return None
        elif isinstance(value, float) and (pd.isna(value) or value != value):
            return None
        return value
    
    cleaned = []
    for pool in server_pools:
        cleaned_pool = {}
        for key, value in pool.items():
            if isinstance(value, dict):
                cleaned_pool[key] = {k: clean_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                cleaned_list = []
                for item in value:
                    if isinstance(item, dict):
                        cleaned_list.append({k: clean_value(v) for k, v in item.items()})
                    else:
                        cleaned_list.append(clean_value(item))
                cleaned_pool[key] = cleaned_list
            else:
                cleaned_pool[key] = clean_value(value)
        cleaned.append(cleaned_pool)
    return cleaned

def update_server_pool(session, ep_id, origin_ip, backup_ip):
    # Convert all pandas values to Python scalars first
    try:
        ep_id = ep_id.item() if hasattr(ep_id, 'item') else ep_id
    except:
        pass
    
    try:
        origin_ip = origin_ip.item() if hasattr(origin_ip, 'item') else origin_ip
    except:
        pass
        
    try:
        backup_ip = backup_ip.item() if hasattr(backup_ip, 'item') else backup_ip
    except:
        pass
    
    # Handle NaN values in input and convert to scalar values
    if pd.isna(ep_id):
        logging.warning("EP ID is NaN, skipping")
        return
    
    # Convert values to strings and handle NaN
    try:
        origin_ip = None if pd.isna(origin_ip) else str(origin_ip).strip()
        if origin_ip == 'nan' or origin_ip == '':
            origin_ip = None
    except:
        origin_ip = None
        
    try:
        backup_ip = None if pd.isna(backup_ip) else str(backup_ip).strip()
        if backup_ip == 'nan' or backup_ip == '':
            backup_ip = None
    except:
        backup_ip = None
    
    # Check if we have any valid IPs
    has_origin = origin_ip is not None and origin_ip != ''
    has_backup = backup_ip is not None and backup_ip != ''
    
    if not has_origin and not has_backup:
        logging.warning(f"No valid IPs for {ep_id}, skipping")
        return
    
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

        # Add origin if missing and valid
        if has_origin and not any(s.get("addr") == origin_ip for s in existing_servers):
            existing_servers.append({
                "addr": origin_ip,
                "port": 80,
                "backup": False,
                "enabled": True
            })

        # Add backup if missing and valid
        if has_backup and not any(s.get("addr") == backup_ip for s in existing_servers):
            existing_servers.append({
                "addr": backup_ip,
                "port": 80,
                "backup": True,
                "enabled": True
            })

        # Enable health check
        pool.setdefault("health", {})["health_check"] = True

        # Clean the server pools data before sending
        cleaned_server_pools = clean_server_pools(server_pools)

        # Send update
        update_response = session.put(url, json={"server_pools": cleaned_server_pools})
        update_response.raise_for_status()
        logging.info(f"Updated {ep_id} with origin ({origin_ip}) and backup ({backup_ip})")
        print(f"✓ Updated {ep_id}")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400:
            logging.error(f"Bad Request for {ep_id}: {e.response.text}")
            print(f"✗ Bad Request for {ep_id} - check data format")
        else:
            logging.error(f"HTTP {e.response.status_code} for {ep_id}: {str(e)}")
            print(f"✗ HTTP {e.response.status_code} for {ep_id}")
    except Exception as e:
        logging.error(f"Failed to update {ep_id}: {str(e)}")
        print(f"✗ Failed to update {ep_id}: {str(e)}")

def main():
    input_file = "update_ips.xlsx"
    if not os.path.exists(input_file):
        print(f"Input file '{input_file}' not found.")
        return

    try:
        df = pd.read_excel(input_file)
        if not {"ep_id", "origin_ip", "backup_ip"}.issubset(df.columns):
            print("Input file must contain 'ep_id', 'origin_ip', and 'backup_ip' columns.")
            return

        session = create_session()
        total = len(df)
        processed = 0
        
        print(f"Processing {total} records...")
        
        for index, row in df.iterrows():
            # Extract values and convert to Python scalars
            ep_id = row['ep_id']
            origin_ip = row['origin_ip']
            backup_ip = row['backup_ip']
            
            # Convert pandas scalars to Python scalars
            try:
                ep_id = ep_id.item() if hasattr(ep_id, 'item') else ep_id
            except:
                pass
            
            # Check if EP ID is valid using a safer method
            ep_id_is_na = False
            try:
                ep_id_is_na = pd.isna(ep_id)
            except:
                ep_id_is_na = ep_id is None or str(ep_id).strip() == ''
            
            if ep_id_is_na:
                print(f"Skipping row {index + 1}: empty EP ID")
                continue
                
            processed += 1
            update_server_pool(session, ep_id, origin_ip, backup_ip)
        
        print(f"Completed processing {processed} valid records out of {total} total rows.")
        
    except Exception as e:
        logging.error(f"Critical error: {str(e)}")
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main() 
