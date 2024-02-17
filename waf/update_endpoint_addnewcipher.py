import requests
import pandas as pd
import json

# Load the Excel file for EP IDs
df = pd.read_excel('update_cipher.xlsx')
ep_ids = df['ep_id'].tolist()

api_key = 'api'
# Replace with your actual API key
headers = {
    'Authorization': f'Basic {api_key}',
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

new_ciphers = [
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305'
]

for ep_id in ep_ids:
    url = f'https://api.fortiweb-cloud.com/v2/application/{str(ep_id).zfill(10)}/endpoint'

    # Fetch the current configuration
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        config = response.json()

        # Append new ciphers to the existing list if it exists, or create it if it doesn't
        existing_ciphers = config['ssl_options'].get('selected_ssl_custom_cipher', [])
        updated_ciphers = existing_ciphers + [cipher for cipher in new_ciphers if cipher not in existing_ciphers]
        config['ssl_options']['selected_ssl_custom_cipher'] = updated_ciphers

        # Update the configuration
        update_response = requests.put(url, headers=headers, data=json.dumps(config))
        if update_response.status_code in [200, 204]:
            print(f"Updated EP ID {ep_id} successfully.")
        else:
            print(f"Failed to update EP ID {ep_id}: {update_response.status_code}, {update_response.text}")
    else:
        print(f"Failed to fetch current configuration for EP ID {ep_id}: {response.status_code}, {response.text}")
