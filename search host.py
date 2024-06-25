import pandas as pd
from shodan import Shodan
import xlsxwriter

# Initialize the Shodan client
api_key = 'API key'
api = Shodan(api_key)

# Load the Excel file containing IP addresses
ip_data = pd.read_excel('ips.xlsx')  # Ensure your IP addresses are in the first column of this file
ip_list = ip_data.iloc[:, 0].tolist()

# Dictionary to store the results
results = {'IP Address': [], 'Hostnames': [], 'Service': []}

# Iterate through each IP address and perform the search
for ip in ip_list:
    try:
        host_info = api.host(ip)
        print(f"Processing IP: {ip}")

        # Extract hostnames
        hostnames = host_info.get('hostnames', [])

        # Attempt to extract service from the 'cloud' dictionary
        service = host_info.get('data', [{}])[0].get('cloud', {}).get('service', '')

        # Save to results if hostnames or service is found
        if hostnames or service:
            results['IP Address'].append(ip)
            results['Hostnames'].append(", ".join(hostnames))
            results['Service'].append(service)

    except Exception as e:
        print(f"Error retrieving information for IP {ip}: {e}")

# Create a DataFrame from the results
results_df = pd.DataFrame(results)

# Save the results to an Excel file
with pd.ExcelWriter('shodan_results.xlsx', engine='xlsxwriter') as writer:
    results_df.to_excel(writer, index=False)
    writer.close()

print("Results have been saved to 'shodan_results.xlsx'.")
