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
import ssl
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass
from queue import Queue
import threading

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# Setup and API credentials
HOST = (".api.cloud.extrahop.com")
ID = ""
SECRET = ""
EXCEL_FILE = "device.xlsx"
MAX_WORKERS = 20  # Increased maximum concurrent workers
INITIAL_BATCH_SIZE = 200  # Increased initial batch size
CONNECTION_POOL_SIZE = 100  # Connection pool size

# Token caching
class TokenCache:
    def __init__(self):
        self.token = None
        self.expiry = None

    def is_valid(self):
        return self.token and self.expiry and datetime.now() < self.expiry

    def set_token(self, token, expires_in=3600):
        self.token = token
        self.expiry = datetime.now() + timedelta(seconds=expires_in)

token_cache = TokenCache()

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

# Connection Pool Manager
class ConnectionPool:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance.initialize()
            return cls._instance

    def initialize(self):
        self.session = self._create_session()
        self.last_used = datetime.now()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=CONNECTION_POOL_SIZE,
            pool_maxsize=CONNECTION_POOL_SIZE
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.verify = False
        return session

    def get_session(self) -> requests.Session:
        current_time = datetime.now()
        if (current_time - self.last_used).total_seconds() > 300:  # 5 minutes
            self.session = self._create_session()
        self.last_used = current_time
        return self.session

@dataclass
class BatchProcessingMetrics:
    total_processed: int = 0
    successful: int = 0
    failed: int = 0
    start_time: Optional[datetime] = None
    
    def calculate_success_rate(self) -> float:
        return self.successful / self.total_processed if self.total_processed > 0 else 0

class BatchSizeManager:
    def __init__(self, initial_size=INITIAL_BATCH_SIZE, min_size=50, max_size=500):
        self.current_size = initial_size
        self.min_size = min_size
        self.max_size = max_size
        self.metrics = BatchProcessingMetrics()
        self.adjustment_threshold = 0.8  # 80% success rate threshold

    def adjust_batch_size(self, success_rate: float):
        if success_rate > self.adjustment_threshold:
            self.increase_batch_size()
        elif success_rate < (self.adjustment_threshold - 0.2):  # If below 60%
            self.decrease_batch_size()

    def increase_batch_size(self):
        new_size = min(int(self.current_size * 1.2), self.max_size)
        if new_size != self.current_size:
            self.current_size = new_size
            logging.info(f"Increased batch size to {self.current_size}")

    def decrease_batch_size(self):
        new_size = max(int(self.current_size * 0.8), self.min_size)
        if new_size != self.current_size:
            self.current_size = new_size
            logging.info(f"Decreased batch size to {self.current_size}")

class DeviceBatch:
    def __init__(self, size: int):
        self.values: List[str] = []
        self.cells: List[Any] = []
        self.field: Optional[str] = None
        self.size = size

    def is_full(self) -> bool:
        return len(self.values) >= self.size

    def add_device(self, value: str, cell: Any, field: str):
        if not self.field:
            self.field = field
        elif self.field != field:
            return False
        
        self.values.append(value)
        self.cells.append(cell)
        return True

    def clear(self):
        self.values.clear()
        self.cells.clear()
        self.field = None

def get_token():
    """Generate and retrieve a temporary API access token with caching and retry logic."""
    max_retries = 3
    retry_delay = 2  # seconds

    for attempt in range(max_retries):
        if token_cache.is_valid():
            return token_cache.token

        try:
            auth = f"{ID}:{SECRET}".encode('utf-8')
            headers = {
                "Authorization": f"Basic {base64.b64encode(auth).decode('utf-8')}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            url = f"https://{HOST}/oauth2/token"
            session = requests.Session()
            response = session.post(url, headers=headers, data="grant_type=client_credentials", timeout=30)
            
            if response.status_code == 200:
                try:
                    token_data = response.json()
                    token = token_data.get('access_token')
                    expires_in = token_data.get('expires_in', 3600)
                    
                    if not token:
                        logging.error("Token not found in response")
                        time.sleep(retry_delay)
                        continue
                        
                    # Refresh token 5 minutes before expiration
                    token_cache.set_token(token, expires_in - 300)
                    return token
                except requests.exceptions.JSONDecodeError:
                    logging.error("Error decoding token response JSON")
            else:
                logging.error(f"Failed to get token: {response.status_code}, Response: {response.text}")
            
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                
        except (requests.exceptions.RequestException, ValueError) as e:
            logging.error(f"Error during token retrieval: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)

    return None

def get_auth_header():
    """Retrieve the authorization header with the token."""
    token = get_token()
    if not token:
        logging.error("Authentication failed: No token retrieved.")
        return None
    return f"Bearer {token}"

def get_tag_id(tag_name, headers):
    """Retrieve the ID of a tag based on its name."""
    session = requests.Session()
    url = f"https://{HOST}/api/v1/tags"
    response = session.get(url, headers=headers)
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
    session = requests.Session()
    url = f"https://{HOST}/api/v1/tags"
    data = {"name": tag_name}
    response = session.post(url, headers=headers, json=data)
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
    """Check and refresh token if expired or about to expire"""
    max_retries = 3
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries):
        try:
            if not token_cache.is_valid():
                new_token = get_token()
                if new_token:
                    headers["Authorization"] = f"Bearer {new_token}"
                    logging.info("Token refreshed successfully")
                    return True
                else:
                    if attempt < max_retries - 1:
                        logging.warning(f"Token refresh attempt {attempt + 1} failed, retrying...")
                        time.sleep(retry_delay)
                        continue
                    else:
                        logging.error("All token refresh attempts failed")
                        return False
            return True
        except Exception as e:
            logging.error(f"Error during token refresh: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            return False
    
    return False

def process_excel_sheet(sheet, headers):
    """Enhanced process_excel_sheet with improved batch processing and memory management"""
    name_col, ipaddr_col, tag_col = None, None, None
    for cell in sheet[1]:
        if cell.value and cell.value.lower() == 'name':
            name_col = cell.column
        elif cell.value and cell.value.lower() == 'ipaddr':
            ipaddr_col = cell.column
        elif cell.value and cell.value.lower() == 'tag':
            tag_col = cell.column

    batch_manager = BatchSizeManager()
    connection_pool = ConnectionPool()
    
    def process_batch(batch: DeviceBatch, tag_id: str) -> bool:
        try:
            session = connection_pool.get_session()
            success = batch_search_and_tag_devices(
                batch.values, batch.field, tag_id, headers, 
                batch.cells, session, batch_manager.metrics
            )
            success_rate = batch_manager.metrics.calculate_success_rate()
            batch_manager.adjust_batch_size(success_rate)
            return success
        except Exception as e:
            logging.error(f"Batch processing error: {str(e)}")
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        current_batch = DeviceBatch(batch_manager.current_size)
        previous_tag = None
        
        for row in sheet.iter_rows(min_row=2):
            if check_memory_usage():
                time.sleep(1)  # Brief pause for memory cleanup
                
            tag_name = row[tag_col - 1].value if tag_col is not None else None
            
            if not tag_name and previous_tag:
                tag_name = previous_tag
                row[tag_col - 1].value = tag_name
            
            if tag_name:
                previous_tag = tag_name
                tag_id = get_tag_id(tag_name, headers) or create_tag(tag_name, headers)
                
                if not tag_id:
                    continue

                # Process name and IP columns
                for col, field in [(name_col, 'name'), (ipaddr_col, 'ipaddr')]:
                    if col is not None and row[col - 1].value:
                        if current_batch.is_full() or (current_batch.field and current_batch.field != field):
                            if current_batch.values:
                                futures.append(
                                    executor.submit(process_batch, current_batch, tag_id)
                                )
                            current_batch = DeviceBatch(batch_manager.current_size)
                        
                        current_batch.add_device(row[col - 1].value, row[col - 1], field)

        # Process final batch
        if current_batch.values:
            futures.append(executor.submit(process_batch, current_batch, tag_id))

        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

def batch_search_and_tag_devices(values: List[str], field: str, tag_id: str, 
                               headers: Dict[str, str], cells: List[Any], 
                               session: requests.Session,
                               metrics: BatchProcessingMetrics) -> bool:
    """Optimized batch processing with connection pooling and metrics tracking"""
    url_search = f"https://{HOST}/api/v1/devices/search"
    success_values = []
    failed_values = []
    all_device_ids = []

    # Update metrics
    metrics.total_processed += len(values)
    
    # Batch device search
    for value, cell in zip(values, cells):
        try:
            data = {"filter": {"field": field, "operand": value, "operator": "="}}
            response = session.post(url_search, headers=headers, json=data, timeout=30)
            
            if response.status_code == 200:
                devices = response.json()
                if devices:
                    all_device_ids.extend([device['id'] for device in devices])
                    success_values.append(value)
                    metrics.successful += 1
                else:
                    failed_values.append(value)
                    cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
                    metrics.failed += 1
                    # Update failed statistics
                    if field == 'name':
                        stats.failed_name_tags.add(value)
                    else:
                        stats.failed_ip_tags.add(value)
            else:
                failed_values.append(value)
                cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
                metrics.failed += 1
                # Update failed statistics
                if field == 'name':
                    stats.failed_name_tags.add(value)
                else:
                    stats.failed_ip_tags.add(value)
                
        except Exception as e:
            logging.error(f"Search request failed for {field} {value}: {str(e)}")
            failed_values.append(value)
            cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
            metrics.failed += 1
            # Update failed statistics
            if field == 'name':
                stats.failed_name_tags.add(value)
            else:
                stats.failed_ip_tags.add(value)

    if not all_device_ids:
        return False

    # Assign tags in batch
    try:
        url_assign = f"https://{HOST}/api/v1/tags/{tag_id}/devices"
        data_assign = {"assign": all_device_ids}
        response_assign = session.post(url_assign, headers=headers, json=data_assign, timeout=30)
        
        if response_assign.status_code == 204:
            # Update success statistics
            for value in success_values:
                if field == 'name':
                    stats.successful_name_tags.add(value)
                else:
                    stats.successful_ip_tags.add(value)
            return True
        else:
            # Mark all values as failed if tag assignment fails
            for value in success_values:
                if field == 'name':
                    stats.failed_name_tags.add(value)
                else:
                    stats.failed_ip_tags.add(value)
            for cell in cells:
                cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
            return False
            
    except Exception as e:
        logging.error(f"Tag assignment request failed: {str(e)}")
        # Mark all values as failed if exception occurs
        for value in success_values:
            if field == 'name':
                stats.failed_name_tags.add(value)
            else:
                stats.failed_ip_tags.add(value)
        for cell in cells:
            cell.fill = PatternFill(start_color="FFFF00", fill_type="solid")
        return False

def print_summary():
    """Print a summary of all tagging operations."""
    duration = datetime.now() - stats.start_time
    logging.info("\n=== Tagging Operation Summary ===")
    logging.info(f"Total processing time: {duration}")
    logging.info(f"Created new tags: {len(stats.created_tags)}")
    if stats.created_tags:
        logging.info("Created tags:")
        for tag in stats.created_tags:
            logging.info(f"  - {tag}")
            
    logging.info(f"Used existing tags: {len(stats.existing_tags)}")
    if stats.existing_tags:
        logging.info("Existing tags:")
        for tag in stats.existing_tags:
            logging.info(f"  - {tag}")
            
    logging.info(f"Successfully tagged by name: {len(stats.successful_name_tags)}")
    if stats.successful_name_tags:
        logging.info("Successfully tagged names:")
        for name in stats.successful_name_tags:
            logging.info(f"  - {name}")
            
    logging.info(f"Failed to tag by name: {len(stats.failed_name_tags)}")
    if stats.failed_name_tags:
        logging.info("Failed name tags:")
        for name in stats.failed_name_tags:
            logging.info(f"  - {name}")
    
    logging.info(f"Successfully tagged by IP: {len(stats.successful_ip_tags)}")
    if stats.successful_ip_tags:
        logging.info("Successfully tagged IPs:")
        for ip in stats.successful_ip_tags:
            logging.info(f"  - {ip}")
            
    logging.info(f"Failed to tag by IP: {len(stats.failed_ip_tags)}")
    if stats.failed_ip_tags:
        logging.info("Failed IP tags:")
        for ip in stats.failed_ip_tags:
            logging.info(f"  - {ip}")

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
