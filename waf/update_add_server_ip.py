import logging
import requests
import pandas as pd
import numpy as np
import keyring
import getpass
import os
import warnings
import json

# ================================
# CONFIGURATION SECTION
# ================================

# Health Check Configuration - Set your preferences here
ENABLE_HEALTH_CHECK = True  # Set to True to enable, False to disable
HEALTH_CHECK_CONFIG = {
    "health_check": True,
    "url": "/",              # Health check URL path
    "interval": 10,          # Check interval in seconds (1-300)
    "timeout": 3,            # Timeout in seconds (1-30)
    "retry": 3,              # Retry count (1-10)
    "method": "head",        # HTTP method: head, get, post
    "code": 200             # Expected response code (200-599)
}

# API Configuration
APP_NAME = "waf"
KEY_NAME = "keyring"
BASE_URL_TEMPLATE = "https://api.appsec.fortinet.com/v2/waf/apps/{}/servers"

# Server Configuration Defaults (based on UI constraints)
DEFAULT_SERVER_CONFIG = {
    "status": "enable",      # Options: enable, disable, maintenance
    "type": "ip",           # Options: ip, domain, dynamic
    "port": 80,             # Range: 1-65534
    "weight": 1,            # Range: 1-9999
    "protocol": "http"      # Options: http, https
}

# File Configuration
INPUT_FILE = "update_ips.xlsx"  # Excel file name
LOG_FILE = "update_server.log"  # Log file name

# ================================
# END CONFIGURATION SECTION
# ================================

# Disable SSL warnings for dev environment
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Logging Configuration
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,
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
                cleaned_pool[key] = {k: clean_value(v) for k, v in value.items() if clean_value(v) is not None}
            elif isinstance(value, list):
                cleaned_list = []
                for item in value:
                    if isinstance(item, dict):
                        cleaned_item = {k: clean_value(v) for k, v in item.items() if clean_value(v) is not None}
                        if cleaned_item:
                            cleaned_list.append(cleaned_item)
                    else:
                        cleaned_item = clean_value(item)
                        if cleaned_item is not None:
                            cleaned_list.append(cleaned_item)
                cleaned_pool[key] = cleaned_list
            else:
                cleaned_value = clean_value(value)
                if cleaned_value is not None:
                    cleaned_pool[key] = cleaned_value
        cleaned.append(cleaned_pool)
    return cleaned

def configure_health_check(pool, enable_health_check=True):
    """
    Configure health check for server pool
    
    Args:
        pool (dict): Server pool configuration
        enable_health_check (bool): Whether to enable health check
    
    Returns:
        dict: Updated server pool configuration
    """
    if not enable_health_check:
        # If health check is disabled, set to false but keep other configs
        if "health" in pool:
            pool["health"]["health_check"] = False
        logging.info("Health check disabled for server pool")
        return pool
    
    # Ensure health section exists
    if "health" not in pool:
        pool["health"] = {}
    
    # Update health check configuration
    pool["health"].update(HEALTH_CHECK_CONFIG)
    
    # Remove fields that might cause issues
    if "content" in pool["health"]:
        del pool["health"]["content"]
    
    logging.info(f"Health check configured: {HEALTH_CHECK_CONFIG}")
    return pool

def update_server_pool(session, ep_id, origin_ip, backup_ip, enable_health_check=True, health_config=None):
    # Safely convert all values
    ep_id_str = safe_convert_to_string(ep_id)
    origin_ip_str = safe_convert_to_string(origin_ip)
    backup_ip_str = safe_convert_to_string(backup_ip)
    
    # Check if EP ID is valid
    if ep_id_str is None:
        logging.warning("EP ID is null/NaN, skipping")
        return False
    
    # Check if we have any valid IPs
    has_origin = origin_ip_str is not None
    has_backup = backup_ip_str is not None
    
    if not has_origin and not has_backup:
        logging.warning(f"No valid IPs for {ep_id_str}, skipping")
        return False
    
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
            return False

        pool = server_pools[0]
        existing_servers = pool.setdefault("server_list", [])

        # Track if we made any changes
        changes_made = False

        # Add origin if missing and valid
        if has_origin and not any(s.get("addr") == origin_ip_str for s in existing_servers):
            # Find the next available idx
            max_idx = max([s.get("idx", 0) for s in existing_servers], default=0)
            
            # Use the first existing server as template
            template_server = existing_servers[0] if existing_servers else None
            new_origin_server = create_server_config(
                origin_ip_str, 
                is_backup=False, 
                template_server=template_server
            )
            new_origin_server["idx"] = max_idx + 1
            
            existing_servers.append(new_origin_server)
            changes_made = True
            logging.info(f"Added origin server {origin_ip_str} for {ep_id_str}")

        # Add backup if missing and valid
        if has_backup and not any(s.get("addr") == backup_ip_str for s in existing_servers):
            # Find the next available idx
            max_idx = max([s.get("idx", 0) for s in existing_servers], default=0)
            
            # Use the first existing server as template
            template_server = existing_servers[0] if existing_servers else None
            new_backup_server = create_server_config(
                backup_ip_str, 
                is_backup=True, 
                template_server=template_server
            )
            new_backup_server["idx"] = max_idx + 1
            
            existing_servers.append(new_backup_server)
            changes_made = True
            logging.info(f"Added backup server {backup_ip_str} for {ep_id_str}")

        if changes_made:
            # Configure health check (after server updates, before PUT request)
            if enable_health_check:
                pool = configure_health_check(pool, enable_health_check)
            
            # Prepare the PUT request using the exact structure from GET response
            # The PUT request needs the full config structure, not just the pool
            put_response = session.put(
                url, 
                json=config,  # Send the full config, not just pool_config
                verify=False
            )
            
            if put_response.status_code == 200:
                health_status = "with health check" if enable_health_check else "without health check"
                print(f"✅ Successfully updated {ep_id_str} {health_status}")
                logging.info(f"Successfully updated {ep_id_str} {health_status}")
                return True
            else:
                print(f"❌ Failed to update {ep_id_str}: {put_response.status_code}")
                logging.error(f"Failed to update {ep_id_str}: {put_response.status_code} - {put_response.text}")
                return False
        else:
            print(f"ℹ️ No server changes needed for {ep_id_str}")
            
            # May still need to update health check configuration
            if enable_health_check:
                pool = configure_health_check(pool, enable_health_check)
                
                # Send the full config with updated health check
                put_response = session.put(
                    url,
                    json=config,  # Send the full config
                    verify=False
                )
                
                if put_response.status_code == 200:
                    print(f"✅ Updated health check for {ep_id_str}")
                    logging.info(f"Updated health check for {ep_id_str}")
                    return True
                else:
                    print(f"❌ Failed to update health check for {ep_id_str}: {put_response.status_code}")
                    logging.error(f"Failed to update health check for {ep_id_str}: {put_response.status_code}")
                    return False
            else:
                logging.info(f"No updates needed for {ep_id_str}")
                return True

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400:
            logging.error(f"Bad Request for {ep_id_str}: {e.response.text}")
            print(f"✗ Bad Request for {ep_id_str} - check data format")
            # Log the request data for debugging
            logging.debug(f"Request data that failed: {json.dumps(config if 'config' in locals() else 'N/A', indent=2)}")
        elif e.response.status_code == 404:
            logging.error(f"Application {ep_id_str} not found")
            print(f"✗ Application {ep_id_str} not found")
        else:
            logging.error(f"HTTP {e.response.status_code} for {ep_id_str}: {str(e)}")
            print(f"✗ HTTP {e.response.status_code} for {ep_id_str}")
    except Exception as e:
        logging.error(f"Failed to update {ep_id_str}: {str(e)}")
        print(f"✗ Failed to update {ep_id_str}: {str(e)}")
        return False

def create_server_config(ip_address, is_backup=False, port=None, weight=None, status=None, template_server=None):
    """
    Create a standardized server configuration based on existing server template
    
    Args:
        ip_address (str): Server IP address
        is_backup (bool): Whether this is a backup server
        port (int): Server port (1-65534), defaults to 80
        weight (int): Server weight (1-9999), defaults to 1
        status (str): Server status (enable/disable/maintenance), defaults to enable
        template_server (dict): Existing server to use as template
    
    Returns:
        dict: Server configuration dictionary
    """
    if template_server:
        # Copy the existing server structure and modify key fields
        config = template_server.copy()
        config["addr"] = ip_address
        config["backup"] = is_backup
        if port:
            config["port"] = port
        if weight:
            config["weight"] = weight
        if status:
            config["status"] = status
    else:
        # Fallback to minimal config if no template available
        config = {
            "addr": ip_address,
            "backup": is_backup,
            "status": status or DEFAULT_SERVER_CONFIG["status"],
            "type": DEFAULT_SERVER_CONFIG["type"],
            "port": port or DEFAULT_SERVER_CONFIG["port"],
            "weight": weight or DEFAULT_SERVER_CONFIG["weight"],
            # Essential fields required by API
            "ssl": False,
            "http2": False,
            "cert_verify": False
        }
    
    # Validate port range
    if not (1 <= config["port"] <= 65534):
        logging.warning(f"Port {config['port']} out of range (1-65534), using default 80")
        config["port"] = 80
    
    # Validate weight range
    if not (1 <= config["weight"] <= 9999):
        logging.warning(f"Weight {config['weight']} out of range (1-9999), using default 1")
        config["weight"] = 1
    
    # Validate status
    valid_statuses = ["enable", "disable", "maintenance"]
    if config["status"] not in valid_statuses:
        logging.warning(f"Invalid status '{config['status']}', using default 'enable'")
        config["status"] = "enable"
    
    return config

def main():
    """Main function"""
    print("=== WAF Server Pool Management ===")
    print("Function: Update server pool configuration based on Excel file")
    
    # Display health check status
    if ENABLE_HEALTH_CHECK:
        print(f"\n✅ Health check enabled: {HEALTH_CHECK_CONFIG}")
    else:
        print("\n❌ Health check disabled")
    
    # Setup session
    session = requests.Session()
    
    # Get API key
    api_key = get_api_key()
    session.headers.update({
        'Authorization': f'Basic {api_key}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    })
    session.verify = False

    if not os.path.exists(INPUT_FILE):
        print(f"Input file '{INPUT_FILE}' not found.")
        return

    try:
        df = pd.read_excel(INPUT_FILE)
        required_columns = {"ep_id", "origin_ip", "backup_ip"}
        if not required_columns.issubset(set(df.columns)):
            print("Input file must contain 'ep_id', 'origin_ip', and 'backup_ip' columns.")
            return

        total = len(df)
        processed = 0
        
        print(f"Processing {total} records...")
        
        for index in range(total):
            row_ep_id = df.iloc[index]['ep_id']
            row_origin_ip = df.iloc[index]['origin_ip']
            row_backup_ip = df.iloc[index]['backup_ip']
            
            if update_server_pool(session, row_ep_id, row_origin_ip, row_backup_ip, ENABLE_HEALTH_CHECK):
                processed += 1
        
        print(f"Completed processing {processed} valid records out of {total} total rows.")
        
    except Exception as e:
        logging.error(f"Critical error: {str(e)}")
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main() 
