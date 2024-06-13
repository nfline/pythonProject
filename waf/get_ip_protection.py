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
        ip_protection_details['ep_id'] = formatted_ep_id
        ip_protection_details['block_country_list'] = ', '.join(ip_protection_details['configs'].get('block_country_list', []))
        
        # Extracting IPs based on their type
        trust_ips = [item['ip'] for item in ip_protection_details['configs'].get('ip_list', []) if item['type'] == 'trust-ip']
        block_ips = [item['ip'] for item in ip_protection_details['configs'].get('ip_list', []) if item['type'] == 'block-ip']
        allow_only_ips = [item['ip'] for item in ip_protection_details['configs'].get('ip_list', []) if item['type'] == 'allow-only-ip']
        
        # Storing IPs as a comma-separated string
        ip_protection_details['trust_ips'] = ', '.join(trust_ips)
        ip_protection_details['block_ips'] = ', '.join(block_ips)
        ip_protection_details['allow_only_ips'] = ', '.join(allow_only_ips)
        
        # Assume we can get app name from somewhere in the response or from another call; for now, adding a placeholder
        ip_protection_details['app_name'] = 'App Name Placeholder'  # Adjust as necessary if available in the response

        # Remove the nested 'configs' dictionary to avoid errors with DataFrame conversion
        ip_protection_details.pop('configs', None)
        
        all_ip_protection_details.append(ip_protection_details)
    else:
        print(f"Failed to fetch IP protection details for EP ID {ep_id}: {response.status_code}")

# Convert the list of IP protection details to a DataFrame
ip_protection_df = pd.DataFrame(all_ip_protection_details)

# Save the DataFrame to an Excel file
ip_protection_df.to_excel('ip_protection_details.xlsx', index=False)
print("IP protection details for all applications have been saved to ip_protection_details.xlsx")
