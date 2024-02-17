import requests
import pandas as pd

# Replace with your actual API key
api_key = 'apikey'
base_url = 'https://api.fortiweb-cloud.com/v2/application'

headers = {
    'Authorization': f'Basic {api_key}',
    'Accept': 'application/json'
}

# Initialize parameters for the API call
params = {
    'size': 30,  # Adjust based on your needs
    'cursor': ''  # Start with no cursor to get the first page
}

all_applications = []

while True:
    response = requests.get(base_url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        all_applications.extend(data['app_list'])  # Use the correct key based on your JSON structure

        # Check if a next_cursor is provided to paginate
        next_cursor = data.get('next_cursor')
        if not next_cursor:  # If no next_cursor, break the loop
            break
        params['cursor'] = next_cursor  # Update cursor for the next request
    else:
        print(f"Failed to fetch applications: {response.status_code}, {response.text}")
        break

# Convert the list of applications to a DataFrame
df = pd.DataFrame(all_applications)

# Save the DataFrame to an Excel file
df.to_excel('applications.xlsx', index=False)
print("All applications information saved to applications.xlsx")
