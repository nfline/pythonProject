import requests
import openpyxl
from openpyxl.styles import PatternFill
import base64
import concurrent.futures
import logging
from datetime import datetime, timedelta
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from threading import Semaphore
import urllib3
import psutil
import warnings

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Setup and API credentials
HOST = ("[subdomain].api.cloud.extrahop.com")
ID = "paste api key here"
SECRET = "paste api key here"
EXCEL_FILE = "device.xlsx"
MAX_WORKERS = 10  # Maximum concurrent workers
BATCH_SIZE = 100  # Batch processing size
CACHE_EXPIRY = 7200  # Cache expiry in seconds (2 hours)
DEVICE_SEARCH_BATCH = 50  # Number of devices to search in one API call

# Token and Tag caching
class Cache:
    def __init__(self):
        self.data = None
        self.expiry = None

    def is_valid(self):
        return self.data and self.expiry and datetime.now() < self.expiry

    def set(self, data, expires_in=CACHE_EXPIRY):
        self.data = data
        self.expiry = datetime.now() + timedelta(seconds=expires_in)

    def get(self):
        return self.data if self.is_valid() else None

class TokenCache(Cache):
    def set_token(self, token, expires_in=CACHE_EXPIRY):
        self.set(token, expires_in)

    def get_token(self):
        return self.get()

class TagCache(Cache):
    def __init__(self):
        super().__init__()
        self.data = {}  # Dictionary of tag_name: tag_id

    def get_tag_id(self, tag_name):
        if self.is_valid() and tag_name in self.data:
            return self.data[tag_name]
        return None

    def add_tag(self, tag_name, tag_id):
        if not self.is_valid():
            self.data = {}
            self.expiry = datetime.now() + timedelta(seconds=CACHE_EXPIRY)
        self.data[tag_name] = tag_id

token_cache = TokenCache()
tag_cache = TagCache()

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
        self.processed_count = 0
        self.start_time = None

stats = TaggingStats()

def create_session():
    """Create a requests session with retry strategy"""
    session = requests.Session()
    retry_strategy = Retry(
        total=5,  # Increase retry attempts
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.verify = False  # Disable SSL verification
    return session

def get_token():
    """Generate and retrieve a temporary API access token with caching."""
    if token_cache.is_valid():
        return token_cache.get_token()

    auth = f"{ID}:{SECRET}".encode('utf-8')
    headers = {
        "Authorization": f"Basic {base64.b64encode(auth).decode('utf-8')}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    url = f"https://{HOST}/oauth2/token"
    session = create_session()
    response = session.post(url, headers=headers, data="grant_type=client_credentials", timeout=30)
    
    if response.status_code != 200:
        logging.error(f"Failed to get token: {response.status_code}, Response: {response.text}")
        return None
    
    try:
        token = response.json().get('access_token')
        expires_in = response.json().get('expires_in', CACHE_EXPIRY)
        token_cache.set_token(token, expires_in)
        return token
    except requests.exceptions.JSONDecodeError:
        logging.error("Error decoding token response JSON.")
        return None

def get_auth_header():
    """Retrieve the authorization header with the token."""
    token = get_token()
    if not token:
        logging.error("Authentication failed: No token retrieved.")
        return None
    return f"Bearer {token}"

def get_tag_id(tag_name, headers):
    """Retrieve the ID of a tag based on its name with caching."""
    # Try to get from cache first
    tag_id = tag_cache.get_tag_id(tag_name)
    if tag_id is not None:
        logging.debug(f"Using cached tag ID for '{tag_name}'")
        return tag_id

    # If not in cache, search for the tag
    url = f"https://{HOST}/api/v1/tags"
    session = create_session()
    response = session.get(url, headers=headers, timeout=30)
    
    if response.status_code != 200:
        logging.error(f"Failed to fetch tags: {response.status_code}, Response: {response.text}")
        return None
    
    try:
        tags = response.json()
        tag_id = next((tag['id'] for tag in tags if tag['name'] == tag_name), None)
        if tag_id:
            logging.info(f"Found existing tag: '{tag_name}' with ID: {tag_id}")
            stats.existing_tags.add(tag_name)
            # Cache the tag ID
            tag_cache.add_tag(tag_name, tag_id)
        else:
            logging.info(f"Tag '{tag_name}' not found in API response.")
        return tag_id
    except requests.exceptions.JSONDecodeError:
        logging.error("Error decoding tags response JSON.")
        return None

def create_tag(tag_name, headers):
    """Create a new tag if it does not exist."""
    url = f"https://{HOST}/api/v1/tags"
    session = create_session()
    data = {"name": tag_name}
    response = session.post(url, headers=headers, json=data, timeout=30)
    
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
    # Cache the newly created tag ID
    tag_cache.add_tag(tag_name, tag_id)
    return tag_id

def check_memory_usage():
    """Monitor system memory usage"""
    process = psutil.Process()
    memory_info = process.memory_info()
    memory_percent = process.memory_percent()
    if memory_percent > 80:  # If memory usage exceeds 80%
        logging.warning(f"High memory usage detected: {memory_percent:.2f}% ({memory_info.rss / 1024 / 1024:.2f} MB)")
        return True
    return False

def refresh_token_if_needed(headers):
    """Check and refresh token if expired"""
    if not token_cache.is_valid():
        new_token = get_token()
        if new_token:
            headers["Authorization"] = f"Bearer {new_token}"
            logging.info("Token refreshed successfully")
            return True
        else:
            logging.error("Failed to refresh token")
            return False
    return True

def batch_search_devices(values, field, headers):
    """Search for multiple devices in a single API call"""
    filters = [{"field": field, "operand": value, "operator": "="} for value in values]
    data = {
        "filter": {
            "operator": "or",
            "rules": filters
        }
    }
    
    session = create_session()
    url_search = f"https://{HOST}/api/v1/devices/search"
    response = session.post(url_search, headers=headers, json=data, timeout=30)
    
    if response.status_code != 200:
        logging.error(f"Batch device search failed: {response.status_code}, Response: {response.text}")
        return None
    
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        logging.error("Error decoding batch device search response JSON")
        return None

def batch_search_and_tag_devices(values, field, tag_id, headers, cells):
    """Batch search and tag devices based on field and values."""
    session = create_session()
    
    # Track success/failure for each device
    success_values = []
    failed_values = []
    success_cells = []
    failed_cells = []
    
    # Check memory usage
    if check_memory_usage():
        time.sleep(5)  # Allow system time for memory cleanup
    
    # Refresh token if needed
    if not refresh_token_if_needed(headers):
        logging.error("Token refresh failed, marking batch as failed")
        for cell in cells:
            cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
        return False
    
    # Process devices in smaller batches for search
    all_device_ids = []
    for i in range(0, len(values), DEVICE_SEARCH_BATCH):
        batch_values = values[i:i + DEVICE_SEARCH_BATCH]
        batch_cells = cells[i:i + DEVICE_SEARCH_BATCH]
        
        devices = batch_search_devices(batch_values, field, headers)
        if not devices:
            for cell in batch_cells:
                cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
            continue

        # Map devices to their search values
        device_map = {}
        for device in devices:
            device_value = device.get(field)
            if device_value in batch_values:
                if device_value not in device_map:
                    device_map[device_value] = []
                device_map[device_value].append(device['id'])

        # Process results
        for value, cell in zip(batch_values, batch_cells):
            if value in device_map:
                all_device_ids.extend(device_map[value])
                success_values.append(value)
                success_cells.append(cell)
            else:
                failed_values.append(value)
                failed_cells.append(cell)

    # Mark failed cells
    for cell in failed_cells:
        cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
    
    if not all_device_ids:
        return False

    # Refresh token before tag assignment
    if not refresh_token_if_needed(headers):
        logging.error("Token refresh failed before tag assignment")
        return False

    # Assign tags in batch
    try:
        url_assign = f"https://{HOST}/api/v1/tags/{tag_id}/devices"
        data_assign = {"assign": all_device_ids}
        response_assign = session.post(url_assign, headers=headers, json=data_assign, timeout=30)
        
        if response_assign.status_code == 204:
            # Only mark successful values
            for value in success_values:
                if field == 'name':
                    stats.successful_name_tags.add(value)
                else:
                    stats.successful_ip_tags.add(value)
            return True
        
        # If tag assignment fails, mark all cells as failed
        for cell in cells:
            cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
        return False
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        logging.error(f"Tag assignment request failed: {str(e)}")
        for cell in cells:
            cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
        return False

def process_excel_sheet(sheet, headers):
    """Process each row for both name and ipaddr columns with batch processing."""
    name_col, ipaddr_col, tag_col = None, None, None
    for cell in sheet[1]:
        if cell.value and cell.value.lower() == 'name':
            name_col = cell.column
        elif cell.value and cell.value.lower() == 'ipaddr':
            ipaddr_col = cell.column
        elif cell.value and cell.value.lower() == 'tag':
            tag_col = cell.column

    previous_tag = None
    semaphore = Semaphore(MAX_WORKERS)
    
    def process_batch(values, field, cells, tag_id):
        with semaphore:
            return batch_search_and_tag_devices(values, field, tag_id, headers, cells)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        current_batch = []
        current_cells = []
        current_field = None
        
        for row in sheet.iter_rows(min_row=2):
            tag_name = row[tag_col - 1].value if tag_col is not None else None
            
            if not tag_name and previous_tag:
                tag_name = previous_tag
                row[tag_col - 1].value = tag_name
            
            if tag_name:
                previous_tag = tag_name
                tag_id = get_tag_id(tag_name, headers) or create_tag(tag_name, headers)
                if not tag_id:
                    logging.error(f"Skipping row, unable to retrieve or create tag: {tag_name}")
                    continue

                # Process name column
                if name_col is not None and row[name_col - 1].value:
                    if len(current_batch) >= BATCH_SIZE:
                        futures.append(executor.submit(process_batch, current_batch.copy(), current_field, current_cells.copy(), tag_id))
                        current_batch = []
                        current_cells = []
                    current_batch.append(row[name_col - 1].value)
                    current_cells.append(row[name_col - 1])
                    current_field = 'name'

                # Process ipaddr column
                if ipaddr_col is not None and row[ipaddr_col - 1].value:
                    if len(current_batch) >= BATCH_SIZE:
                        futures.append(executor.submit(process_batch, current_batch.copy(), current_field, current_cells.copy(), tag_id))
                        current_batch = []
                        current_cells = []
                    current_batch.append(row[ipaddr_col - 1].value)
                    current_cells.append(row[ipaddr_col - 1])
                    current_field = 'ipaddr'

        # Process the last batch
        if current_batch:
            futures.append(executor.submit(process_batch, current_batch, current_field, current_cells, tag_id))

        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

def print_summary():
    """Print a summary of all tagging operations."""
    duration = datetime.now() - stats.start_time
    logging.info("\n=== Tagging Operation Summary ===")
    logging.info(f"Total processing time: {duration}")
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
    stats.start_time = datetime.now()
    
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

