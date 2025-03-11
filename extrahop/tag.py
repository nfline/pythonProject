import requests
import openpyxl
from openpyxl.styles import PatternFill
import base64
import concurrent.futures

# Setup and API credentials
HOST = ("[subdomain].api.cloud.extrahop.com")
ID = "paste api key here"
SECRET = "paste api key here"
EXCEL_FILE = "device.xlsx"

def get_token():
    """Generate and retrieve a temporary API access token."""
    auth = f"{ID}:{SECRET}".encode('utf-8')
    headers = {
        "Authorization": f"Basic {base64.b64encode(auth).decode('utf-8')}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    url = f"https://{HOST}/oauth2/token"
    response = requests.post(url, headers=headers, data="grant_type=client_credentials")
    
    if response.status_code != 200:
        print(f"Failed to get token: {response.status_code}, Response: {response.text}")
        return None
    
    try:
        return response.json().get('access_token')
    except requests.exceptions.JSONDecodeError:
        print("Error decoding token response JSON.")
        return None

def get_auth_header():
    """Retrieve the authorization header with the token."""
    token = get_token()
    if not token:
        print("Authentication failed: No token retrieved.")
        return None
    return f"Bearer {token}"

def get_tag_id(tag_name, headers):
    """Retrieve the ID of a tag based on its name."""
    url = f"https://{HOST}/api/v1/tags"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Failed to fetch tags: {response.status_code}, Response: {response.text}")
        return None
    
    try:
        tags = response.json()
        return next((tag['id'] for tag in tags if tag['name'] == tag_name), None)
        if not tag_id:
            print(f"Tag '{tag_name}' not found in API response.")  
        return tag_id
    except requests.exceptions.JSONDecodeError:
        print("Error decoding tags response JSON.")  
        return None
    
def create_tag(tag_name, headers):
    """Create a new tag if it does not exist."""
    url = f"https://{HOST}/api/v1/tags"
    data = {"name": tag_name}
    response = requests.post(url, headers=headers, json=data)
    if response.status_code != 201:
        print(f"[ERROR] Failed to create tag '{tag_name}': {response.status_code}, Response: {response.text}")
        print(f"[DEBUG] Response Headers: {response.headers}")
        return None

    try:
        # First, try to get the ID from JSON response
        tag_id = response.json().get('id')
    except requests.exceptions.JSONDecodeError:
        print("[WARNING] No JSON in response, checking headers for tag ID...")
        tag_id = None

    # If JSON is empty, extract tag ID from 'Location' header
    if not tag_id and 'Location' in response.headers:
        tag_id = response.headers['Location'].split('/')[-1]  # Extract the last part of the URL (the ID)
        print(f"[INFO] Extracted tag ID from Location header: {tag_id}")

    if not tag_id:
        print(f"[ERROR] Created tag '{tag_name}', but could not retrieve its ID!")
        return None

    print(f"[INFO] Successfully created tag '{tag_name}' with ID: {tag_id}")
    return tag_id


def search_and_tag_devices(value, field, tag_id, headers, cell):
    """Search and tag devices based on field and value, mark cell if not found."""
    url_search = f"https://{HOST}/api/v1/devices/search"
    data = {"filter": {"field": field, "operand": value, "operator": "="}}
    response = requests.post(url_search, headers=headers, json=data)
    
    if response.status_code != 200:
        print(f"Device search failed: {response.status_code}, Response: {response.text}")
        cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
        return False
    
    try:
        devices = response.json()
        if not devices:
            print(f"No devices found for: {field} {value}")
            cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
            return False
        
        device_ids = [device['id'] for device in devices]
        url_assign = f"https://{HOST}/api/v1/tags/{tag_id}/devices"
        data_assign = {"assign": device_ids}
        response_assign = requests.post(url_assign, headers=headers, json=data_assign)
        
        if response_assign.status_code == 204:
            print(f"Successfully assigned tag to: {field} {value}")
            return True
    except requests.exceptions.JSONDecodeError:
        print("Error decoding device search response JSON.")
    
    cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
    return False

def process_excel_sheet(sheet, headers):
    """Process each row for both name and ipaddr columns, mark and print results."""
    name_col, ipaddr_col, tag_col = None, None, None
    for cell in sheet[1]:
        if cell.value and cell.value.lower() == 'name':
            name_col = cell.column
        elif cell.value and cell.value.lower() == 'ipaddr':
            ipaddr_col = cell.column
        elif cell.value and cell.value.lower() == 'tag':
            tag_col = cell.column

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for row in sheet.iter_rows(min_row=2):
            tag_name = row[tag_col - 1].value if tag_col is not None else None
            if not tag_name:
                continue
            tag_id = get_tag_id(tag_name, headers) or create_tag(tag_name, headers)
            if not tag_id:
                print(f"Skipping row, unable to retrieve or create tag: {tag_name}")
                continue

            if name_col is not None and row[name_col - 1].value:
                futures.append(executor.submit(search_and_tag_devices, row[name_col - 1].value, 'name', tag_id, headers, row[name_col - 1]))
            if ipaddr_col is not None and row[ipaddr_col - 1].value:
                futures.append(executor.submit(search_and_tag_devices, row[ipaddr_col - 1].value, 'ipaddr', tag_id, headers, row[ipaddr_col - 1]))

def main():
    headers = {"Authorization": get_auth_header()}
    if not headers["Authorization"]:
        print("Authentication failed. Exiting...")
        return
    
    wb = openpyxl.load_workbook(EXCEL_FILE)
    sheet = wb.active
    process_excel_sheet(sheet, headers)
    wb.save("updated_" + EXCEL_FILE)
    print("Workbook saved with color-coded results for not found entries.")

if __name__ == "__main__":
    main()

