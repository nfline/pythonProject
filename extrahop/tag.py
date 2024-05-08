import requests
import openpyxl
from openpyxl.styles import PatternFill
import base64

# API Credentials and Setup
HOST = "[subdomain].api.cloud.extrahop.com"
ID = "paste id"
SECRET = "paste to here"
TAG = "tag name"
EXCEL_FILE = "device.xlsx"  # This should be an Excel file

def get_token():
    """Generate and retrieve a temporary API access token."""
    auth = f"{ID}:{SECRET}".encode('utf-8')
    headers = {
        "Authorization": f"Basic {base64.b64encode(auth).decode('utf-8')}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    url = f"https://{HOST}/oauth2/token"
    response = requests.post(url, headers=headers, data="grant_type=client_credentials")
    return response.json()['access_token'] if response.status_code == 200 else None

def get_auth_header():
    """Retrieve the appropriate authorization header."""
    return f"Bearer {get_token()}"

def get_tag_id(tag_name):
    """Retrieve the ID of a tag based on its name."""
    headers = {"Authorization": get_auth_header()}
    url = f"https://{HOST}/api/v1/tags"
    response = requests.get(url, headers=headers)
    tags = response.json() if response.status_code == 200 else []
    return next((tag['id'] for tag in tags if tag['name'] == tag_name), None)

def find_devices_by_ip_or_name(sheet):
    """Retrieve devices based on IP addresses or names from an Excel file."""
    devices = []
    headers = {"Authorization": get_auth_header()}
    for row in sheet.iter_rows(min_row=2, max_row=sheet.max_row, min_col=1, max_col=1):
        value = row[0].value
        if not value:
            continue
        field = "ipaddr" if '.' in value else "name"
        url = f"https://{HOST}/api/v1/devices/search"
        data = {"filter": {"field": field, "operand": value.strip(), "operator": "="}}
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200 and response.json():
            devices.extend(response.json())
        else:
            row[0].fill = PatternFill(start_color="FFFF00", fill_type="solid")  # Yellow for not found
    return devices

def assign_tag(tag_id, devices, sheet):
    """Assign the specified tag to a list of devices using POST method."""
    headers = {"Authorization": get_auth_header(), "Content-Type": "application/json"}
    url = f"https://{HOST}/api/v1/tags/{tag_id}/devices"
    device_ids = [device['id'] for device in devices]
    data = {"assign": device_ids, "unassign": []}
    response = requests.post(url, headers=headers, json=data)
    if response.status_code != 204:
        for device in devices:
            # Find the row with the device ID and color it red
            for row in sheet.iter_rows(min_row=2, max_row=sheet.max_row, min_col=1, max_col=1):
                if row[0].value == device['display_name']:
                    row[0].fill = PatternFill(start_color="FF0000", fill_type="solid")  # Red for failed tagging

def main():
    wb = openpyxl.load_workbook(EXCEL_FILE)
    sheet = wb.active
    tag_id = get_tag_id(TAG)
    if not tag_id:
        print(f"Tag {TAG} does not exist.")
        return

    devices = find_devices_by_ip_or_name(sheet)
    if devices:
        assign_tag(tag_id, devices, sheet)
    wb.save("updated_" + EXCEL_FILE)
    print("Workbook saved with color-coded results.")

if __name__ == "__main__":
    main()
