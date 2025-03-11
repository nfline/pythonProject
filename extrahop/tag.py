import requests
import openpyxl
from openpyxl.styles import PatternFill
import base64
import concurrent.futures

# Setup and API credentials
HOST = ("[subdomain].api.cloud.extrahop.com")
ID = "paste api key here"
SECRET = "paste api key here"
TAG = "paste tag here"
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
    return response.json()['access_token'] if response.status_code == 200 else None


def get_auth_header():
    """Retrieve the authorization header with the token."""
    return f"Bearer {get_token()}"


def get_tag_id(tag_name, headers):
    """Retrieve the ID of a tag based on its name."""
    url = f"https://{HOST}/api/v1/tags"
    response = requests.get(url, headers=headers)
    tags = response.json() if response.status_code == 200 else []
    return next((tag['id'] for tag in tags if tag['name'] == tag_name), None)


def search_and_tag_devices(value, field, tag_id, headers, cell):
    """Search and tag devices based on field and value, mark cell if not found."""
    url_search = f"https://{HOST}/api/v1/devices/search"
    data = {"filter": {"field": field, "operand": value, "operator": "="}}
    response = requests.post(url_search, headers=headers, json=data)
    if response.status_code == 200 and response.json():
        device_ids = [device['id'] for device in response.json()]
        print(device_ids)
        url_assign = f"https://{HOST}/api/v1/tags/{tag_id}/devices"
        data_assign = {"assign": device_ids}
        response_assign = requests.post(url_assign, headers=headers, json=data_assign)
        if response_assign.status_code == 204:
            print(f"Successfully assigned tag to: {field} {value}")
            return True
    print(f"Failed to assign tag to: {field} {value}")
    cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")  # Mark cell yellow if not found
    return False


def process_excel_sheet(sheet, tag_id, headers):
    """Process each row for both name and ipaddr columns, mark and print results."""
    name_col, ipaddr_col = None, None
    # Determine which columns have 'name' and 'ipaddr'
    for cell in sheet[1]:  # Assuming first row is headers
        if cell.value.lower() == 'name':
            name_col = cell.column
        elif cell.value.lower() == 'ipaddr':
            ipaddr_col = cell.column

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for row in sheet.iter_rows(min_row=2):
            if name_col is not None and row[name_col - 1].value:
                futures.append(executor.submit(search_and_tag_devices, row[name_col - 1].value, 'name', tag_id, headers,
                                               row[name_col - 1]))
            if ipaddr_col is not None and row[ipaddr_col - 1].value:
                futures.append(
                    executor.submit(search_and_tag_devices, row[ipaddr_col - 1].value, 'ipaddr', tag_id, headers,
                                    row[ipaddr_col - 1]))


def main():
    headers = {"Authorization": get_auth_header()}
    wb = openpyxl.load_workbook(EXCEL_FILE)
    sheet = wb.active
    tag_id = get_tag_id(TAG, headers)
    if not tag_id:
        print(f"Tag {TAG} does not exist.")
        return

    process_excel_sheet(sheet, tag_id, headers)
    wb.save("updated_" + EXCEL_FILE)
    print("Workbook saved with color-coded results for not found entries.")


if __name__ == "__main__":
    main()

