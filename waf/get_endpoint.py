import pandas as pd
import requests
import json

# Assuming you've already obtained a list of ep_ids and saved it to an Excel file
df = pd.read_excel('applications.csv')
ep_ids = df['ep_id'].tolist()  # Adjust the column name as necessary

api_key = 'apikey'
base_url_template = 'https://api.fortiweb-cloud.com/v2/application/{}/endpoint'

headers = {
    'Authorization': f'Basic {api_key}',
    'Accept': 'application/json'
}

all_endpoint_details = []

for ep_id in ep_ids:
    formatted_ep_id = str(ep_id).zfill(10)  # Adjust the number based on the required length
    response = requests.get(base_url_template.format(formatted_ep_id), headers=headers)

    if response.status_code == 200:
        endpoint_details = response.json()
        # Directly include 'ep_id' in endpoint_details
        endpoint_details['ep_id'] = formatted_ep_id  # Add this line to include ep_id
        # Here, adapt the structure according to the provided JSON.
        if 'ssl_options' in endpoint_details:
            ssl_options_df = pd.json_normalize(endpoint_details['ssl_options'])
            # You might want to rename columns in ssl_options_df here to reflect they are SSL options
            endpoint_details.update(ssl_options_df.to_dict('records')[0])
            # Remove the 'ssl_options' if you've normalized it into separate columns
        endpoint_details.pop('ssl_options', None)
        all_endpoint_details.append(endpoint_details)
    else:
        print(f"Failed to fetch details for EP ID {ep_id}: {response.status_code}")

# Convert the list of endpoint details to a DataFrame
details_df = pd.DataFrame(all_endpoint_details)

# Save the DataFrame to an Excel file
details_df.to_excel('endpoint_details.xlsx', index=False)
print("Endpoint details for all applications have been saved to endpoint_details.xlsx")
