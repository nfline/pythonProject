# URL Validator
# Validates URLs from an Excel file and checks their accessibility

import pandas as pd
import requests

# Excel file path
excel_path = 'test url.xlsx'

# Read Excel file
df = pd.read_excel(excel_path)

# Add a new column for validation results
df['Status'] = ''

# Iterate through each URL in the DataFrame
for index, row in df.iterrows():
    url = row['URL']
    try:
        response = requests.get(url, timeout=5)
        # Determine URL validity based on HTTP response status code
        if response.status_code == 200:
            df.at[index, 'Status'] = 'Valid'
        else:
            df.at[index, 'Status'] = 'Invalid'
    except requests.RequestException:
        df.at[index, 'Status'] = 'Invalid'

# Save results to a new Excel file
output_path = 'validated_urls.xlsx'
df.to_excel(output_path, index=False)