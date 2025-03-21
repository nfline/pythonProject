import subprocess
import requests
import json
import logging
import os
from azure.storage.blob import BlobServiceClient
from datetime import datetime

# Configure logging
logging.basicConfig(filename='sync_users.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# ThousandEyes API configuration
te_api_token = os.getenv('THOUSANDEYES_TOKEN')
te_api_url = "https://api.thousandeyes.com/v6/tests.json"

# Azure Storage configuration
connection_string = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
container_name = "thousandeyes-data"
blob_name = f"thousandeyes_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

def log_and_print(message, level="info"):
    print(message)
    if level == "info":
        logging.info(message)
    elif level == "error":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)

# Azure CLI command to get user EMAIL list
def get_azure_users():
    command = 'az ad group member list --group "group" --query "[].mail" --output json'
    log_and_print("Running Azure CLI command to get user emails...")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Azure CLI command failed: {result.stderr}")
    emails = [email.lower() for email in json.loads(result.stdout)]
    log_and_print(f"Azure users retrieved: {emails}")
    return emails

# Get ThousandEyes existing user EMAIL list
def get_1000eyes_users(api_token):
    url = "https://api.thousandeyes.com/v6/users.json"
    headers = {"Authorization": f"Bearer {api_token}"}
    log_and_print("Fetching existing ThousandEyes users...")
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"ThousandEyes API request failed: {response.text}")
    users = response.json().get("users", [])
    emails = [user["email"].lower() for user in users if "email" in user]
    log_and_print(f"ThousandEyes users retrieved: {emails}")
    return emails

# Create new user to ThousandEyes
def create_1000eyes_user(api_token, email, login_account_group_id, account_group_id, role_ids):
    url = "https://api.thousandeyes.com/v6/users.json"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "name": email.split("@")[0],  # Use email prefix as name
        "email": email,
        "loginAccountGroupId": login_account_group_id,
        "accountGroupRoles": [
            {
                "accountGroupId": account_group_id,
                "roleIds": role_ids
            }
        ],
        "allAccountGroupRoleIds": role_ids
    }
    log_and_print(f"Creating user {email} in ThousandEyes...")
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 201:
        log_and_print(f"Failed to create user {email}: {response.text}")
    else:
        log_and_print(f"Successfully created user: {email}")

def get_thousandeyes_data():
    """
    Fetch data from ThousandEyes API
    """
    headers = {
        'Authorization': f'Bearer {te_api_token}',
        'Content-Type': 'application/json',
    }
    
    try:
        response = requests.get(te_api_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from ThousandEyes: {e}")
        return None

def upload_to_azure(data):
    """
    Upload data to Azure Blob Storage
    """
    try:
        # Create the BlobServiceClient object
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        
        # Get container client
        container_client = blob_service_client.get_container_client(container_name)
        
        # Create container if it doesn't exist
        if not container_client.exists():
            container_client.create_container()
        
        # Get blob client
        blob_client = container_client.get_blob_client(blob_name)
        
        # Convert data to JSON string
        json_data = json.dumps(data)
        
        # Upload data
        blob_client.upload_blob(json_data, overwrite=True)
        
        print(f"Successfully uploaded data to {blob_name}")
        return True
    except Exception as e:
        print(f"Error uploading to Azure: {e}")
        return False

# Main logic
def sync_users(api_token, login_account_group_id, account_group_id, role_ids):
    azure_users = get_azure_users()
    te_users = get_1000eyes_users(api_token)
    
    new_users = set(azure_users) - set(te_users)
    log_and_print(f"New users to create: {new_users}")
    
    if new_users:
        log_and_print(f"Creating {len(new_users)} new users in ThousandEyes...")
        for email in new_users:
            create_1000eyes_user(api_token, email, login_account_group_id, account_group_id, role_ids)
    else:
        log_and_print("No new users to create.")

def main():
    """
    Main function to sync ThousandEyes data to Azure
    """
    # Get data from ThousandEyes
    data = get_thousandeyes_data()
    if not data:
        print("Failed to get data from ThousandEyes")
        return
    
    # Upload to Azure
    success = upload_to_azure(data)
    if not success:
        print("Failed to upload data to Azure")
        return
    
    print("Data sync completed successfully")

# Execute script
if __name__ == "__main__":
    THOUSAND_EYES_API_TOKEN = os.getenv('THOUSANDEYES_TOKEN')  # Get from environment variable
    LOGIN_ACCOUNT_GROUP_ID = os.getenv('TE_LOGIN_ACCOUNT_GROUP_ID')  # Replace with correct loginAccountGroupId
    ACCOUNT_GROUP_ID = os.getenv('TE_ACCOUNT_GROUP_ID')  # Replace with correct accountGroupId
    ROLE_IDS = [57, 1140]  # Replace with correct role IDs
    
    if os.getenv('SYNC_USERS') == 'true':
        sync_users(THOUSAND_EYES_API_TOKEN, LOGIN_ACCOUNT_GROUP_ID, ACCOUNT_GROUP_ID, ROLE_IDS)
    else:
        main()