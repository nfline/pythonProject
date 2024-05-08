import requests
import openpyxl
from openpyxl.styles import PatternFill
import base64
import concurrent.futures

# API Credentials and Setup
HOST = "***.api.cloud.extrahop.com"
ID = "Paste API key here"
SECRET = "Paste API secret here"
TAG = "Paste tag name"
EXCEL_FILE = "device.xlsx"  # This should be an Excel file
def get_token():
    auth = f"{ID}:{SECRET}".encode('utf-8')
    headers = {
        "Authorization": f"Basic {base64.b64encode(auth).decode('utf-8')}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    url = f"https://{HOST}/oauth2/token"
    response = requests.post(url, headers=headers, data="grant_type=client_credentials")
    return response.json()['access_token'] if response.status_code == 200 else None

def get_auth_header():
    return f"Bearer {get_token()}"

def get_tag_id(tag_name, headers):
    url = f"https://{HOST}/api/v1/tags"
    response = requests.get(url, headers=headers)
    tags = response.json() if response.status_code == 200 else []
    return next((tag['id'] for tag in tags if tag['name'] == tag_name), None)

def search_and_tag_devices(value, field, tag_id, headers):
    url_search = f"https://{HOST}/api/v1/devices/search"
    data = {"filter": {"field": field, "operand": value, "operator": "="}}
    response = requests.post(url_search, headers=headers, json=data)
    if response.status_code == 200 and response.json():
        device_ids = [device['id'] for device in response.json()]
        url_assign = f"https://{HOST}/api/v1/tags/{tag_id}/devices"
        data_assign = {"assign": device_ids, "unassign": []}
        response_assign = requests.post(url_assign, headers=headers, json=data_assign)
        return response_assign.status_code == 204, value
    return False, value

def process_excel_sheet(sheet, tag_id, headers):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Create a mapping of future tasks to row values for tracking
        future_to_row = {
            executor.submit(search_and_tag_devices, row[0].value, 'name' if row[0].column == 1 else 'ipaddr', tag_id, headers): row
            for row in sheet.iter_rows(min_row=2, min_col=1, max_col=2)
        }
        for future in concurrent.futures.as_completed(future_to_row):
            success, value = future.result()
            row = future_to_row[future]
            if success:
                # Print a success message including the value that was successfully tagged
                print(f"Successfully assigned tag to: {value}")
            else:
                # Color the cell yellow if the tagging failed
                for cell in row:
                    cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")  # Yellow for not found or failed
                # Print a message indicating the failure to tag for this value
                print(f"Failed to assign tag to: {value}")


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
