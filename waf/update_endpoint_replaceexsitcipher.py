import pandas as pd
import requests
import json

# Load EP IDs from Excel
df = pd.read_excel('update_cipher.xlsx')
ep_ids = df['ep_id'].tolist()  # Adjust the column name as necessary

api_key = 'api'
headers = {
    'Authorization': f'Basic {api_key}',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# New cipher suites to be added
ciphers = ['ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305']

for ep_id in ep_ids:
    formatted_ep_id = str(ep_id).zfill(10)  # Ensure EP ID is correctly formatted
    url = f'https://api.fortiweb-cloud.com/v2/application/{formatted_ep_id}/endpoint'

    # Fetch current configuration for the endpoint
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        current_config = response.json()
        # Update the cipher suite in the current configuration
        current_config['ssl_options']['selected_ssl_custom_cipher'] = ciphers

        # Submit the updated configuration
        update_response = requests.put(url, headers=headers, data=json.dumps(current_config))
        if update_response.status_code in [200, 204]:
            print(f"SSL configuration for EP ID {formatted_ep_id} updated successfully.")
        else:
            print(f"Failed to update SSL configuration for EP ID {formatted_ep_id}: {update_response.status_code}, {update_response.text}")
    else:
        print(f"Failed to fetch current configuration for EP ID {formatted_ep_id}: {response.status_code}, {response.text}")
