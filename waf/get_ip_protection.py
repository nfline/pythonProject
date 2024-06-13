import pandas as pd
import requests

# Load EP IDs from an Excel file
df = pd.read_excel('applications.csv')
ep_ids = df['ep_id'].tolist()  # Adjust the column name as necessary

api_key = 'apikey'
base_url_template = 'https://api.fortiweb-cloud.com/v2/application/{}/ip_protection'

headers = {
    'Authorization': f'Basic {api_key}',
    'Accept': 'application/json'
}

all_ip_protection_details = []

for ep_id in ep_ids:
    formatted_ep_id = str(ep_id).zfill(10)  # Adjust the number based on the required length
    response = requests.get(base_url_template.format(formatted_ep_id), headers=headers)

    if response.status_code == 200:
        ip_protection_details = response.json()
        # Add 'ep_id' to ip_protection_details for easier tracking
        ip_protection_details['ep_id'] = formatted_ep_id
        all_ip_protection_details.append(ip_protection_details)
    else:
        print(f"Failed to fetch IP protection details for EP ID {ep_id}: {response.status_code}")

# Convert the list of IP protection details to a DataFrame
ip_protection_df = pd.DataFrame(all_ip_protection_details)

# Save the DataFrame to an Excel file
ip_protection_df.to_excel('ip_protection_details.xlsx', index=False)
print("IP protection details for all applications have been saved to ip_protection_details.xlsx")
