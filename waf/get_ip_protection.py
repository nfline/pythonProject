import pandas as pd
import requests

# Load EP IDs from an Excel file
df = pd.read_excel('applications.xlsx')
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
        ip_protection_details = response.json().get('configs', {})
        # Include 'ep_id' in the data
        ip_protection_details['ep_id'] = formatted_ep_id

        # Handle 'block_country_list'
        ip_protection_details['block_country_list'] = ', '.join(ip_protection_details.get('block_country_list', []))

        # Process 'ip_list'
        trust_ip = []
        block_ip = []
        allow_only_ip = []
        for ip_entry in ip_protection_details.get('ip_list', []):
            if ip_entry['type'] == 'trust-ip':
                trust_ip.append(ip_entry['ip'])
            elif ip_entry['type'] == 'block-ip':
                block_ip.append(ip_entry['ip'])
            elif ip_entry['type'] == 'allow-only-ip':
                allow_only_ip.append(ip_entry['ip'])

        ip_protection_details['trust_ips'] = ', '.join(trust_ip)
        ip_protection_details['block_ips'] = ', '.join(block_ip)
        ip_protection_details['allow_only_ips'] = ', '.join(allow_only_ip)

        # Clean up the original keys if needed
        ip_protection_details.pop('ip_list', None)
        all_ip_protection_details.append(ip_protection_details)
        print(f"Success to fetch IP protection details for EP ID {ep_id}: {response.status_code}")
    else:
        print(f"Failed to fetch IP protection details for EP ID {ep_id}: {response.status_code}")

# Convert the list of IP protection details to a DataFrame
ip_protection_df = pd.DataFrame(all_ip_protection_details)

# Save the DataFrame to an Excel file
ip_protection_df.to_excel('ip_protection_details.xlsx', index=False)
print("IP protection details for all applications have been saved to ip_protection_details.xlsx")
