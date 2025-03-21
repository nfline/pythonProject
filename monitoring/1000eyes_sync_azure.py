import requests
import json
import os
from azure.storage.blob import BlobServiceClient
from datetime import datetime

# ThousandEyes API configuration
te_api_token = os.getenv('THOUSANDEYES_TOKEN')
te_api_url = "https://api.thousandeyes.com/v6/tests.json"

# Azure Storage configuration
connection_string = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
container_name = "thousandeyes-data"
blob_name = f"thousandeyes_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

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

if __name__ == "__main__":
    main()