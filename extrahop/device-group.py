import requests
import pandas as pd
import numpy as np
import json

# API Credentials and URLs
client_id = 'paste your client id'
client_secret = 'paste your client secret'
token_url = 'https://[subdomain].api.cloud.extrahop.com/oauth2/token'
api_url = 'https://[subdomain].api.cloud.extrahop.com/api/v1/devicegroups/[device-group id]'

def get_token(client_id, client_secret):
    """Retrieve an OAuth token."""
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    response = requests.post(token_url, data=data)
    if response.status_code == 200:
        token = response.json().get('access_token')
        print("Token generated successfully:", token)
        return token
    else:
        print("Failed to obtain token. Status code:", response.status_code)
        print("Response:", response.text)
        return None

def update_device_group(token, rules):
    """Send a single update for all rules."""
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Creating nested filter structure based on ExtraHop API
    payload = {
        "filter": {
            "operator": "and",
            "rules": [
                {
                    "operator": "or",
                    "rules": rules
                }
            ]
        }
    }
    print("Sending payload:", json.dumps(payload, indent=4))
    response = requests.patch(api_url, headers=headers, json=payload)
    print("Status Code:", response.status_code)
    try:
        print("Response content:", response.json())
    except ValueError:
        print("No content returned or response not JSON.")

def clean_and_prepare_data(df, field):
    """Prepare data from dataframe, removing NaN values."""
    df = df.dropna(subset=[field])  # Drop rows where the column 'field' is NaN
    return [{'field': field, 'operand': row, 'operator': '=', 'is_regex': False} for row in df[field]]

def read_and_prepare_data(file_path):
    """Read data from an Excel file and prepare for sending."""
    df = pd.read_excel(file_path)
    tags = clean_and_prepare_data(df, 'tag')
    names = clean_and_prepare_data(df, 'name')
    ipaddrs = clean_and_prepare_data(df, 'ipaddr')
    return tags + names + ipaddrs  # Combine all rules into a single list

def main():
    file_path = 'device.xlsx'  # Update this to your Excel file path
    token = get_token(client_id, client_secret)
    if token:
        rules = read_and_prepare_data(file_path)
        update_device_group(token, rules)

if __name__ == "__main__":
    main()
