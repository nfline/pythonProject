"""
Azure NSG Finder and Traffic Analyzer

This script provides functionalities to:
1. Find Network Security Groups (NSGs) associated with a specific IP address
2. Retrieve NSG flow logs configuration
3. Execute Kusto Query Language (KQL) queries against Log Analytics workspaces

Features:
- Azure Resource Graph queries for efficient resource discovery
- Structured logging and error handling
- Multi-step validation process
- Support for both public and private IP addresses
- Automated report generation

Version: 2.1.0
"""

import os
import json
import subprocess
import ipaddress
import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

# Import required modules
import argparse
import sys
from .utils.logger import setup_logger, ColorPrinter
from .utils.azure_cli import run_az_command, check_az_login
from .models.nsg import NSGAnalyzer
from .models.flow_logs import FlowLogsManager
from .reports.excel import generate_excel_report
from .exceptions import (
    InvalidIPError,
    AzureCLIError,
    NSGNotFoundError,
    FlowLogsConfigError,
    WorkspaceAccessError,
    QueryExecutionError
)

class NSGTrafficAnalyzer:
    """Main analyzer class for NSG traffic analysis"""
    
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.output_dir = self._setup_output_directory()
        self.logger = setup_logger()
        self.nsg_analyzer = NSGAnalyzer(target_ip, self.logger)
        self.flow_logs_manager = FlowLogsManager(self.logger)
        
    def _setup_output_directory(self) -> str:
        """Create output directory structure"""
        output_dir = os.path.join("output", f"analysis_{self.target_ip}")
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
        
    def _validate_input(self, time_range_hours: int) -> Tuple[bool, str]:
        """Validate input parameters
        
        Args:
            time_range_hours: Query time range in hours
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Validate IP address
        try:
            ip_obj = ipaddress.ip_address(self.target_ip)
            if time_range_hours < 1 or time_range_hours > 720:
                return False, "Time range must be between 1 and 720 hours"
                
            # Detect IP type
            if ip_obj.is_private:
                self.logger.info(f"Detected private IP address: {self.target_ip}")
            else:
                self.logger.info(f"Detected public IP address: {self.target_ip}")
                
            return True, ""
        except ValueError:
            return False, f"Invalid IP address format: {self.target_ip}"

    def full_analysis(self, time_range_hours: int = 24):
        """Execute complete analysis workflow"""
        try:
            # Input validation
            valid, error_msg = self._validate_input(time_range_hours)
            if not valid:
                raise InvalidIPError(self.target_ip, error_msg)
                
            # Phase 1: NSG Discovery
            self.logger.info("Starting NSG discovery phase")
            nsg_ids = self.nsg_analyzer.find_associated_nsgs()
            
            if not nsg_ids:
                error_msg = f"No NSGs found associated with target IP: {self.target_ip}"
                self.logger.warning(error_msg)
                ColorPrinter.print_warning(error_msg)
                raise NSGNotFoundError(self.target_ip)

            # Phase 2: Flow Logs Configuration
            self.logger.info("Retrieving flow logs configuration")
            flow_configs = self.flow_logs_manager.get_configurations(nsg_ids)
            
            # Phase 3: Log Analytics Processing
            self.logger.info("Processing Log Analytics workspaces")
            workspace_map = self.flow_logs_manager.get_workspace_mapping(flow_configs)
            
            if not workspace_map:
                error_msg = "No Log Analytics workspaces found for the NSGs"
                self.logger.warning(error_msg)
                ColorPrinter.print_warning(error_msg)
                raise FlowLogsConfigError(nsg_ids[0], "No Log Analytics workspace configured")
                
            # Phase 4: Query Execution
            self.logger.info("Executing KQL queries")
            query_results = self._execute_queries(workspace_map, time_range_hours)
            
            # Phase 5: Report Generation
            self.logger.info("Generating final report")
            generate_excel_report(
                nsg_info=self.nsg_analyzer.get_discovery_data(),
                flow_configs=flow_configs,
                query_results=query_results,
                output_path=os.path.join(self.output_dir, f"report_{self.target_ip}.xlsx")
            )
            
            ColorPrinter.print_success("Analysis completed successfully")
            return True

        except InvalidIPError as ip_err:
            self.logger.error(f"Invalid IP address: {str(ip_err)}")
            ColorPrinter.print_error(f"Input validation failed: {str(ip_err)}")
        except NSGNotFoundError as nsg_err:
            self.logger.error(f"NSG discovery failed: {str(nsg_err)}")
            ColorPrinter.print_error(f"NSG not found: {str(nsg_err)}")
        except FlowLogsConfigError as flow_err:
            self.logger.error(f"Flow logs configuration issue: {str(flow_err)}")
            ColorPrinter.print_error(f"Flow logs error: {str(flow_err)}")
        except WorkspaceAccessError as ws_err:
            self.logger.error(f"Workspace access failed: {str(ws_err)}")
            ColorPrinter.print_error(f"Workspace error: {str(ws_err)}")
        except QueryExecutionError as q_err:
            self.logger.error(f"Query execution failed: {str(q_err)}")
            ColorPrinter.print_error(f"Query error: {str(q_err)}")
        except subprocess.CalledProcessError as cpe:
            self.logger.error(f"Azure CLI command failed: {cpe.stderr}")
            ColorPrinter.print_error(f"Azure CLI error: {cpe.output}")
            raise AzureCLIError(str(cpe.cmd), str(cpe.output))
        except Exception as e:
            self.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
            ColorPrinter.print_error(f"Critical error: {str(e)}")
        
        return False

    def _execute_queries(self, workspace_map: Dict[str, str],
                        time_range_hours: int) -> Dict[str, Any]:
        """Execute KQL queries against identified workspaces"""
        results = {}
        query_generator = KQLQueryBuilder(self.target_ip, time_range_hours)
        
        for nsg_id, workspace_id in workspace_map.items():
            try:
                self.logger.info(f"Executing query for NSG: {nsg_id}")
                query = query_generator.build_traffic_analysis_query()
                
                # Use in-memory query instead of temp file when possible
                if len(query) < 1000:  # For small queries, pass directly
                    result = run_az_command(
                        f"az monitor log-analytics query --workspace {workspace_id} "
                        f"--analytics-query \"{query}\" -o json")
                else:
                    # For larger queries, use temp file approach
                    query_file = query_generator.save_temp_query()
                    self.logger.debug(f"Using query file: {query_file}")
                    result = run_az_command(
                        f"az monitor log-analytics query --workspace {workspace_id} "
                        f"--analytics-query @{query_file} -o json")
                
                if result is None:
                    raise WorkspaceAccessError(workspace_id, "Failed to query workspace")
                    
                results[nsg_id] = self._process_query_result(result)
                self.logger.info(f"Query for NSG {nsg_id} returned {len(result)} results")
                    
            except Exception as e:
                error_msg = f"Query failed for NSG {nsg_id}: {str(e)}"
                self.logger.error(error_msg)
                if isinstance(e, WorkspaceAccessError):
                    raise
                raise QueryExecutionError(query, workspace_id, error_msg)
                
        # Clean up temporary files
        query_generator.cleanup_temp_files()
        return results

    def _process_query_result(self, raw_result: List[Dict]) -> Dict:
        """Process and standardize query results
        
        Extracts meaningful metrics from raw query results:
        - Total number of flows
        - Inbound/outbound traffic volume
        - Unique ports in use
        - Actions taken (allowed/denied)
        """
        processed = {
            'total_flows': len(raw_result),
            'inbound_bytes': 0,
            'outbound_bytes': 0,
            'ports': set(),
            'actions': {}
        }
        
        for flow in raw_result:
            # Extract ports
            if 'DestPort_d' in flow:
                processed['ports'].add(flow['DestPort_d'])
                
            # Count actions
            if 'Action_s' in flow:
                action = flow.get('Action_s')
                processed['actions'][action] = processed['actions'].get(action, 0) + 1
                
            # Determine direction and add bytes
            if flow.get('SrcIP_s') == self.target_ip:
                processed['outbound_bytes'] += flow.get('FlowBytes_d', 0)
            else:
                processed['inbound_bytes'] += flow.get('FlowBytes_d', 0)
                
        return processed

class KQLQueryBuilder:
    """Build and manage KQL queries"""
    
    def __init__(self, target_ip: str, time_range_hours: int):
        self.target_ip = target_ip
        self.time_range = time_range_hours
        self.temp_dir = "temp_queries"
        self.query_cache = {}  # Cache queries to avoid regenerating
        os.makedirs(self.temp_dir, exist_ok=True)
        
    def build_traffic_analysis_query(self) -> str:
        """Construct main traffic analysis query
        
        Creates an optimized KQL query that filters for traffic involving
        the target IP address within the specified time range
        """
        # Check cache first
        cache_key = f"{self.target_ip}_{self.time_range}"
        if cache_key in self.query_cache:
            return self.query_cache[cache_key]
            
        # Calculate the time range with proper format
        time_ago = f"{self.time_range}h"
            
        query = f"""
        AzureNetworkAnalytics_CL
        | where TimeGenerated >= ago({time_ago})
        | where SrcIP_s == '{self.target_ip}' or DestIP_s == '{self.target_ip}'
        | project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, Protocol_s,
                  NSG_s, Subnet_s, VM_s, Direction_s, 
                  Action_s, FlowStatus_s, FlowBytes_d
        | sort by TimeGenerated desc
        """
        
        # Store in cache
        self.query_cache[cache_key] = query
        return query

    def save_temp_query(self) -> str:
        """Save query to temporary file"""
        temp_path = os.path.join(self.temp_dir, f"query_{self.target_ip}_{int(time.time())}.kql")
        with open(temp_path, 'w') as f:
            f.write(self.build_traffic_analysis_query())
        return temp_path
        
    def cleanup_temp_files(self, max_age_hours: int = 24):
        """Clean up old temporary query files
        
        Args:
            max_age_hours: Maximum age of files to keep, in hours
        """
        try:
            current_time = datetime.now()
            for filename in os.listdir(self.temp_dir):
                file_path = os.path.join(self.temp_dir, filename)
                file_modified = datetime.fromtimestamp(os.path.getmtime(file_path))
                if (current_time - file_modified) > timedelta(hours=max_age_hours):
                    os.remove(file_path)
        except Exception as e:
            # Just log errors but don't fail the main process
            print(f"Failed to clean up temp files: {str(e)}")

def main():
    """Main entry point function"""
    parser = argparse.ArgumentParser(
        description="Find associated Azure NSGs and analyze traffic logs by IP address",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument("ip_address",
        help="Target IP address to analyze (IPv4/IPv6)")
    parser.add_argument("--time-range", type=int, default=24,
        help="Query time range in hours")
    parser.add_argument("--verbose", action="store_true",
        help="Enable verbose logging")
    parser.add_argument("--output-dir", 
        help="Custom output directory for reports")
    
    args = parser.parse_args()
    
    try:
        # Initialize logging system
        log_level = logging.DEBUG if args.verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("nsg_analysis.log"),
                logging.StreamHandler()
            ])
        
        # IP address format validation
        try:
            ipaddress.ip_address(args.ip_address)
            # Set timezone to UTC
            os.environ['TZ'] = 'UTC'
            if hasattr(time, 'tzset'):  # Only available on Unix
                time.tzset()
        except ValueError:
            raise InvalidIPError(args.ip_address)
            
        # Check Azure CLI login status
        if not check_az_login():
            sys.exit(1)
        
        # Execute analysis
        analyzer = NSGTrafficAnalyzer(args.ip_address)
        success = analyzer.full_analysis(args.time_range)
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        ColorPrinter.print_warning("Operation cancelled by user")
        sys.exit(130)
    except InvalidIPError as ip_err:
        ColorPrinter.print_error(f"IP validation error: {str(ip_err)}")
        sys.exit(1)
    except AzureCLIError as az_err:
        ColorPrinter.print_error(f"Azure CLI error: {str(az_err)}")
        sys.exit(1)
    except Exception as e:
        ColorPrinter.print_error(f"Critical error: {str(e)}")
        sys.exit(1)

# 确保在直接运行脚本时执行main函数，而在作为模块导入时不执行
if __name__ == "__main__":
    # 添加当前目录到Python路径，确保相对导入能够工作
    import os
    import sys
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    main()
