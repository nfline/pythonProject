import requests
import openpyxl
from openpyxl.styles import PatternFill
import base64

# API Credentials and Setup
HOST = "**".api.cloud.extrahop.com"
ID = "***"
SECRET = "***"
TAG = "***"
EXCEL_FILE = "device.xlsx"  # Ensure this is the correct file path

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

def find_and_assign_tags(sheet, tag_id):
    """Retrieve devices by name or IP and assign tags, handling dynamic column locations."""
    headers = {"Authorization": get_auth_header(), "Content-Type": "application/json"}
    url_search = f"https://{HOST}/api/v1/devices/search"
    url_assign = f"https://{HOST}/api/v1/tags/{tag_id}/devices"

    # Identify columns for 'name' and 'ipaddr'
    header_row = sheet[1]
    name_col = ip_col = None
    for cell in header_row:
        if cell.value.lower() == 'name':
            name_col = cell.column
        elif cell.value.lower() == 'ipaddr':
            ip_col = cell.column

    # Process each row after the header
    for row in sheet.iter_rows(min_row=2, max_row=sheet.max_row):
        for col in (name_col, ip_col):
            if col is None:
                continue
            value = row[col - 1].value  # Adjusting for zero-based index
            if not value:
                continue
            field = 'ipaddr' if col == ip_col else 'name'
            data = {"filter": {"field": field, "operand": value, "operator": "="}}
            response = requests.post(url_search, headers=headers, json=data)
            if response.status_code == 200 and response.json():
                device_ids = [device['id'] for device in response.json()]
                data_assign = {"assign": device_ids, "unassign": []}
                response_assign = requests.post(url_assign, headers=headers, json=data_assign)
                if response_assign.status_code == 204:
                    print(f"Successfully assigned tag to {field}: {value}")
            else:
                # Device not found, color the row yellow
                row[col - 1].fill = PatternFill(start_color="FFFF00", fill_type="solid")

def main():
    wb = openpyxl.load_workbook(EXCEL_FILE)
    sheet = wb.active
    tag_id = get_tag_id(TAG)
    if not tag_id:
        print(f"Tag {TAG} does not exist.")
        return

    find_and_assign_tags(sheet, tag_id)
    wb.save("updated_" + EXCEL_FILE)
    print("Workbook saved with color-coded results for not found entries.")

if __name__ == "__main__":
    main()
