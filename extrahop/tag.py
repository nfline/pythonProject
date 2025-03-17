import requests
import openpyxl
from openpyxl.styles import PatternFill
import base64
import concurrent.futures
import logging
from datetime import datetime
import os

# Setup and API credentials
HOST = ("[subdomain].api.cloud.extrahop.com")
ID = "paste api key here"
SECRET = "paste api key here"
EXCEL_FILE = "device.xlsx"

# Setup logging
def setup_logging():
    log_filename = f"tagging_operations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    return log_filename

# Global tracking variables
class TaggingStats:
    def __init__(self):
        self.successful_name_tags = set()
        self.failed_name_tags = set()
        self.successful_ip_tags = set()
        self.failed_ip_tags = set()
        self.created_tags = set()
        self.existing_tags = set()

stats = TaggingStats()

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
        logging.error(f"Failed to fetch tags: {response.status_code}, Response: {response.text}")
        return None
    
    try:
        tags = response.json()
        tag_id = next((tag['id'] for tag in tags if tag['name'] == tag_name), None)
        if tag_id:
            logging.info(f"Found existing tag: '{tag_name}' with ID: {tag_id}")
            stats.existing_tags.add(tag_name)
        else:
            logging.info(f"Tag '{tag_name}' not found in API response.")
        return tag_id
    except requests.exceptions.JSONDecodeError:
        logging.error("Error decoding tags response JSON.")
        return None

def create_tag(tag_name, headers):
    """Create a new tag if it does not exist."""
    url = f"https://{HOST}/api/v1/tags"
    data = {"name": tag_name}
    response = requests.post(url, headers=headers, json=data)
    if response.status_code != 201:
        logging.error(f"Failed to create tag '{tag_name}': {response.status_code}, Response: {response.text}")
        return None

    try:
        tag_id = response.json().get('id')
    except requests.exceptions.JSONDecodeError:
        logging.warning("No JSON in response, checking headers for tag ID...")
        tag_id = None

    if not tag_id and 'Location' in response.headers:
        tag_id = response.headers['Location'].split('/')[-1]
        logging.info(f"Extracted tag ID from Location header: {tag_id}")

    if not tag_id:
        logging.error(f"Created tag '{tag_name}', but could not retrieve its ID!")
        return None

    logging.info(f"Successfully created new tag '{tag_name}' with ID: {tag_id}")
    stats.created_tags.add(tag_name)
    return tag_id

def search_and_tag_devices(value, field, tag_id, headers, cell):
    """Search and tag devices based on field and value, mark cell if not found."""
    url_search = f"https://{HOST}/api/v1/devices/search"
    data = {"filter": {"field": field, "operand": value, "operator": "="}}
    response = requests.post(url_search, headers=headers, json=data)
    
    if response.status_code != 200:
        logging.error(f"Device search failed for {field} {value}: {response.status_code}, Response: {response.text}")
        cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
        if field == 'name':
            stats.failed_name_tags.add(value)
        else:
            stats.failed_ip_tags.add(value)
        return False
    
    try:
        devices = response.json()
        if not devices:
            logging.warning(f"No devices found for: {field} {value}")
            cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
            if field == 'name':
                stats.failed_name_tags.add(value)
            else:
                stats.failed_ip_tags.add(value)
            return False
        
        device_ids = [device['id'] for device in devices]
        url_assign = f"https://{HOST}/api/v1/tags/{tag_id}/devices"
        data_assign = {"assign": device_ids}
        response_assign = requests.post(url_assign, headers=headers, json=data_assign)
        
        if response_assign.status_code == 204:
            logging.info(f"Successfully assigned tag to: {field} {value}")
            if field == 'name':
                stats.successful_name_tags.add(value)
            else:
                stats.successful_ip_tags.add(value)
            return True
    except requests.exceptions.JSONDecodeError:
        logging.error(f"Error decoding device search response JSON for {field} {value}")
    
    cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
    if field == 'name':
        stats.failed_name_tags.add(value)
    else:
        stats.failed_ip_tags.add(value)
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

    if not all([name_col, ipaddr_col, tag_col]):
        logging.error("Required columns (name, ipaddr, tag) not found in Excel file")
        return

    last_tag_name = None
    last_tag_id = None

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for row in sheet.iter_rows(min_row=2):
            current_tag_name = row[tag_col - 1].value if tag_col is not None else None
            
            # If current tag is empty, use the last tag
            if not current_tag_name:
                if last_tag_name:
                    current_tag_name = last_tag_name
                    current_tag_id = last_tag_id
                    logging.info(f"Using previous tag '{current_tag_name}' for row {row[0].row}")
                else:
                    logging.warning(f"Skipping row {row[0].row}: No tag specified and no previous tag available")
                    continue
            else:
                # Get or create new tag
                current_tag_id = get_tag_id(current_tag_name, headers) or create_tag(current_tag_name, headers)
                if not current_tag_id:
                    logging.error(f"Skipping row {row[0].row}, unable to retrieve or create tag: {current_tag_name}")
                    continue
                last_tag_name = current_tag_name
                last_tag_id = current_tag_id

            # Process name and IP address
            if name_col is not None and row[name_col - 1].value:
                futures.append(executor.submit(search_and_tag_devices, row[name_col - 1].value, 'name', current_tag_id, headers, row[name_col - 1]))
            if ipaddr_col is not None and row[ipaddr_col - 1].value:
                futures.append(executor.submit(search_and_tag_devices, row[ipaddr_col - 1].value, 'ipaddr', current_tag_id, headers, row[ipaddr_col - 1]))

def print_summary():
    """Print a summary of all tagging operations."""
    logging.info("\n=== Tagging Operation Summary ===")
    logging.info(f"Created new tags: {len(stats.created_tags)}")
    logging.info(f"Used existing tags: {len(stats.existing_tags)}")
    logging.info(f"Successfully tagged by name: {len(stats.successful_name_tags)}")
    logging.info(f"Failed to tag by name: {len(stats.failed_name_tags)}")
    logging.info(f"Successfully tagged by IP: {len(stats.successful_ip_tags)}")
    logging.info(f"Failed to tag by IP: {len(stats.failed_ip_tags)}")
    
    if stats.failed_name_tags:
        logging.info("\nFailed name tags:")
        for name in stats.failed_name_tags:
            logging.info(f"- {name}")
    
    if stats.failed_ip_tags:
        logging.info("\nFailed IP tags:")
        for ip in stats.failed_ip_tags:
            logging.info(f"- {ip}")

def main():
    log_filename = setup_logging()
    logging.info("Starting tagging operations...")
    
    headers = {"Authorization": get_auth_header()}
    if not headers["Authorization"]:
        logging.error("Authentication failed. Exiting...")
        return
    
    wb = openpyxl.load_workbook(EXCEL_FILE)
    sheet = wb.active
    process_excel_sheet(sheet, headers)
    wb.save("updated_" + EXCEL_FILE)
    
    print_summary()
    logging.info(f"Workbook saved as 'updated_{EXCEL_FILE}'")
    logging.info(f"Detailed log saved as '{log_filename}'")

if __name__ == "__main__":
    main()


