import logging
import requests
import pandas as pd
import numpy as np
import keyring
import getpass
import os
import warnings
import json

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

def is_null_or_nan(value):
    """Safely check if a value is null, NaN, or empty"""
    try:
        if value is None:
            return True
        if hasattr(value, 'item'):
            value = value.item()
        if isinstance(value, float) and np.isnan(value):
            return True
        if str(value).strip().lower() in ['nan', 'none', '']:
            return True
        return False
    except:
        return True

def safe_convert_to_string(value):
    """Safely convert a pandas/numpy value to string"""
    try:
        if is_null_or_nan(value):
            return None
        if hasattr(value, 'item'):
            value = value.item()
        result = str(value).strip()
        if result.lower() in ['nan', 'none', '']:
            return None
        return result
    except:
        return None

def clean_server_pools(server_pools):
    """Clean server pools data to handle NaN values for JSON compliance"""
    def clean_value(value):
        if is_null_or_nan(value):
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
    # Safely convert all values
    ep_id_str = safe_convert_to_string(ep_id)
    origin_ip_str = safe_convert_to_string(origin_ip)
    backup_ip_str = safe_convert_to_string(backup_ip)
    
    # Check if EP ID is valid
    if ep_id_str is None:
        logging.warning("EP ID is null/NaN, skipping")
        return
    
    # Check if we have any valid IPs
    has_origin = origin_ip_str is not None
    has_backup = backup_ip_str is not None
    
    if not has_origin and not has_backup:
        logging.warning(f"No valid IPs for {ep_id_str}, skipping")
        return
    
    formatted_ep_id = ep_id_str.zfill(10)
    url = BASE_URL_TEMPLATE.format(formatted_ep_id)
    
    try:
        # First, get the current configuration
        response = session.get(url, timeout=30)
        response.raise_for_status()
        full_config = response.json()
        
        # Get the result section
        config = full_config.get('result', {})
        server_pools = config.get("server_pools", [])
        
        if not server_pools:
            logging.warning(f"No server pools found for {ep_id_str}")
            return

        pool = server_pools[0]
        existing_servers = pool.setdefault("server_list", [])

        # Track if we made any changes
        changes_made = False

        # Add origin if missing and valid
        if has_origin and not any(s.get("addr") == origin_ip_str for s in existing_servers):
            existing_servers.append({
                "addr": origin_ip_str,
                "port": 80,
                "backup": False,
                "enabled": True
            })
            changes_made = True
            logging.info(f"Added origin server {origin_ip_str} for {ep_id_str}")

        # Add backup if missing and valid
        if has_backup and not any(s.get("addr") == backup_ip_str for s in existing_servers):
            existing_servers.append({
                "addr": backup_ip_str,
                "port": 80,
                "backup": True,
                "enabled": True
            })
            changes_made = True
            logging.info(f"Added backup server {backup_ip_str} for {ep_id_str}")

        if not changes_made:
            print(f"⊙ No changes needed for {ep_id_str}")
            return

        # Enable health check
        pool.setdefault("health", {})["health_check"] = True

        # Clean the server pools data before sending
        cleaned_server_pools = clean_server_pools(server_pools)
        
        # Prepare the complete configuration for PUT request
        # Use the complete original structure but with updated server_pools
        updated_config = config.copy()
        updated_config["server_pools"] = cleaned_server_pools

        # Send update with the complete configuration
        update_response = session.put(url, json=updated_config)
        update_response.raise_for_status()
        logging.info(f"Updated {ep_id_str} with origin ({origin_ip_str}) and backup ({backup_ip_str})")
        print(f"✓ Updated {ep_id_str}")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400:
            logging.error(f"Bad Request for {ep_id_str}: {e.response.text}")
            print(f"✗ Bad Request for {ep_id_str} - check data format")
            # Log the request data for debugging
            logging.debug(f"Request data that failed: {json.dumps(updated_config if 'updated_config' in locals() else 'N/A', indent=2)}")
        else:
            logging.error(f"HTTP {e.response.status_code} for {ep_id_str}: {str(e)}")
            print(f"✗ HTTP {e.response.status_code} for {ep_id_str}")
    except Exception as e:
        logging.error(f"Failed to update {ep_id_str}: {str(e)}")
        print(f"✗ Failed to update {ep_id_str}: {str(e)}")

def main():
    input_file = "update_ips.xlsx"
    if not os.path.exists(input_file):
        print(f"Input file '{input_file}' not found.")
        return

    try:
        df = pd.read_excel(input_file)
        required_columns = {"ep_id", "origin_ip", "backup_ip"}
        if not required_columns.issubset(set(df.columns)):
            print("Input file must contain 'ep_id', 'origin_ip', and 'backup_ip' columns.")
            return

        session = create_session()
        total = len(df)
        processed = 0
        
        print(f"Processing {total} records...")
        
        for index in range(len(df)):
            # Get values by index to avoid pandas issues
            ep_id = df.iloc[index]['ep_id']
            origin_ip = df.iloc[index]['origin_ip']
            backup_ip = df.iloc[index]['backup_ip']
            
            # Check if EP ID is valid using our safe function
            if is_null_or_nan(ep_id):
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
