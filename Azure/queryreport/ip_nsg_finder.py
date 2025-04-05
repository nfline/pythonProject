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
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple

# Import required modules
import argparse
import sys
import pandas as pd

# Terminal output colors
class ColorPrinter:
    """Class for color-coded console output"""
    
    @staticmethod
    def print_info(text):
        """Print informational message"""
        print(f"\033[94m[INFO]\033[0m {text}")

    @staticmethod
    def print_success(text):
        """Print success message"""
        print(f"\033[92m[SUCCESS]\033[0m {text}")

    @staticmethod
    def print_warning(text):
        """Print warning message"""
        print(f"\033[93m[WARNING]\033[0m {text}")

    @staticmethod
    def print_error(text):
        """Print error message"""
        print(f"\033[91m[ERROR]\033[0m {text}")


def setup_logger():
    """Configure logger"""
    logger = logging.getLogger("NSGLogger")
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler
    fh = logging.FileHandler('nsg_analysis.log')
    fh.setFormatter(formatter)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def run_az_command(command):
    """Execute Azure CLI command and return JSON result"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        ColorPrinter.print_error(f"Command execution failed: {e.stderr}")
        return None
    except json.JSONDecodeError:
        ColorPrinter.print_warning("Return result is not valid JSON")
        return None


def check_az_login():
    """Check Azure login status"""
    try:
        subprocess.run(
            "az account show",
            shell=True,
            check=True,
            capture_output=True
        )
        ColorPrinter.print_success("Azure CLI logged in")
        return True
    except subprocess.CalledProcessError:
        ColorPrinter.print_error("Please login using 'az login' first")
        return False


class NSGTrafficAnalyzer:
    """Main analyzer class for NSG traffic analysis"""
    
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.output_dir = self._setup_output_directory()
        self.logger = setup_logger()
        
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

    def find_associated_nsgs(self) -> List[str]:
        """Find NSGs associated with target IP"""
        self.logger.info(f"Searching for NSGs associated with IP: {self.target_ip}")
        
        # Direct resource graph query to find NSGs with rules containing the IP
        nsg_query = f"""
        Resources
        | where type =~ 'microsoft.network/networksecuritygroups'
        | mv-expand rules=properties.securityRules
        | where rules.properties.destinationAddressPrefixes contains '{self.target_ip}'
           or rules.properties.sourceAddressPrefixes contains '{self.target_ip}'
           or rules.properties.destinationAddressPrefix contains '{self.target_ip}'
           or rules.properties.sourceAddressPrefix contains '{self.target_ip}'
        | project id, name, resourceGroup, location
        """
        
        nsg_result = run_az_command(f"az graph query -q \"{nsg_query}\"")
        
        if not nsg_result or 'data' not in nsg_result or not nsg_result['data']:
            ColorPrinter.print_warning(f"No NSGs found directly containing IP: {self.target_ip}")
            self.logger.info("No NSGs found with explicit rules for the target IP")
            
            # Search for the IP in network interfaces
            self.logger.info("Searching for network interfaces with the target IP...")
            nic_query = f"""
            Resources
            | where type =~ 'microsoft.network/networkinterfaces'
            | mv-expand ipconfigs=properties.ipConfigurations
            | where ipconfigs.properties.privateIPAddress =~ '{self.target_ip}'
            | project id, name, resourceGroup, nsgId = tostring(properties.networkSecurityGroup.id)
            | where isnotempty(nsgId)
            """
            
            nic_result = run_az_command(f"az graph query -q \"{nic_query}\"")
            
            if nic_result and 'data' in nic_result and nic_result['data']:
                nsg_ids = [nic['nsgId'] for nic in nic_result['data'] if 'nsgId' in nic]
                self.logger.info(f"Found {len(nsg_ids)} NSGs from network interfaces")
                return nsg_ids
            
            # Search for the IP in subnets
            self.logger.info("Searching for subnets containing the target IP...")
            subnet_query = """
            Resources
            | where type =~ 'microsoft.network/virtualnetworks'
            | mv-expand subnet=properties.subnets
            | project vnetName=name, subnetName=subnet.name, 
                      subnetPrefix=subnet.properties.addressPrefix, 
                      nsgId = tostring(subnet.properties.networkSecurityGroup.id)
            | where isnotempty(nsgId)
            """
            
            subnet_result = run_az_command(f"az graph query -q \"{subnet_query}\"")
            
            if subnet_result and 'data' in subnet_result and subnet_result['data']:
                # Check if IP is in any subnet
                nsg_ids = []
                for subnet in subnet_result['data']:
                    try:
                        if 'subnetPrefix' in subnet and subnet['subnetPrefix']:
                            subnet_network = ipaddress.ip_network(subnet['subnetPrefix'])
                            ip_addr = ipaddress.ip_address(self.target_ip)
                            if ip_addr in subnet_network:
                                nsg_ids.append(subnet['nsgId'])
                                self.logger.info(f"IP {self.target_ip} found in subnet {subnet['subnetName']}")
                    except ValueError:
                        continue
                
                if nsg_ids:
                    self.logger.info(f"Found {len(nsg_ids)} NSGs from subnets")
                    return nsg_ids
            
            self.logger.warning("No NSGs found associated with the target IP")
            return []
        else:
            nsg_ids = [nsg['id'] for nsg in nsg_result['data']]
            self.logger.info(f"Found {len(nsg_ids)} NSGs with rules containing the target IP")
            return nsg_ids

    def get_flow_logs_config(self, nsg_ids: List[str]) -> Dict[str, Dict]:
        """Get flow logs configuration for the NSGs"""
        self.logger.info("Retrieving flow logs configuration...")
        flow_logs_config = {}
        
        for nsg_id in nsg_ids:
            # Extract resource group and name from the ID
            parts = nsg_id.split('/')
            resource_group = next((parts[i+1] for i, part in enumerate(parts) if part.lower() == 'resourcegroups'), None)
            nsg_name = parts[-1]
            
            if not resource_group or not nsg_name:
                self.logger.warning(f"Could not extract resource group or name from NSG ID: {nsg_id}")
                continue
                
            try:
                # First check if the NSG exists
                nsg_check = run_az_command(f"az network nsg show --name {nsg_name} --resource-group {resource_group}")
                
                if not nsg_check:
                    self.logger.warning(f"NSG {nsg_name} in resource group {resource_group} not found")
                    continue
                    
                # Then check for flow logs
                result = run_az_command(f"az network watcher flow-log show --nsg {nsg_name} --resource-group {resource_group}")
                
                if result:
                    workspace_id = None
                    # Extract workspace ID from the configuration if it exists
                    if 'flowAnalyticsConfiguration' in result:
                        analytics_config = result.get('flowAnalyticsConfiguration', {})
                        if 'networkWatcherFlowAnalyticsConfiguration' in analytics_config:
                            workspace_id = analytics_config['networkWatcherFlowAnalyticsConfiguration'].get('workspaceResourceId')
                    
                    flow_logs_config[nsg_id] = {
                        "enabled": result.get("enabled", False),
                        "retention_days": result.get("retentionPolicy", {}).get("days", 0),
                        "storage_id": result.get("storageId"),
                        "workspace_id": workspace_id
                    }
                    self.logger.info(f"Retrieved flow logs config for NSG: {nsg_name}")
                else:
                    self.logger.warning(f"Could not retrieve flow logs for NSG: {nsg_name}")
            except Exception as e:
                self.logger.error(f"Error getting flow logs for NSG {nsg_id}: {str(e)}")
        
        return flow_logs_config

    def get_workspace_mapping(self, flow_configs: Dict[str, Dict]) -> Dict[str, str]:
        """Get workspace ID mapping from flow logs configuration"""
        workspace_map = {}
        
        for nsg_id, config in flow_configs.items():
            if config.get("enabled", False) and config.get("workspace_id"):
                workspace_map[nsg_id] = config["workspace_id"]
                self.logger.info(f"Mapped NSG {nsg_id} to workspace {config['workspace_id']}")
        
        return workspace_map

    def build_kql_query(self, time_range_hours: int) -> str:
        """Build KQL query for NSG flow logs"""
        query = f"""
        AzureNetworkAnalytics_CL
        | where TimeGenerated >= ago({time_range_hours}h)
        | where SrcIP_s == '{self.target_ip}' or DestIP_s == '{self.target_ip}'
        | project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, Protocol_s,
                  NSG_s, Subnet_s, Direction_s, 
                  Action_s, FlowStatus_s, FlowBytes_d
        | sort by TimeGenerated desc
        """
        return query

    def execute_queries(self, workspace_map: Dict[str, str], time_range_hours: int) -> Dict[str, Any]:
        """Execute KQL queries against identified workspaces"""
        results = {}
        
        for nsg_id, workspace_id in workspace_map.items():
            try:
                # Extract workspace name from full resource ID
                workspace_name = workspace_id.split('/')[-1]
                self.logger.info(f"Executing query for NSG {nsg_id} on workspace {workspace_name}")
                
                # Create query
                query = self.build_kql_query(time_range_hours)
                
                # Save query to temp file
                temp_dir = "temp_queries"
                os.makedirs(temp_dir, exist_ok=True)
                query_file = os.path.join(temp_dir, f"query_{int(time.time())}.kql")
                
                with open(query_file, 'w') as f:
                    f.write(query)
                
                # Execute query
                result = run_az_command(f"az monitor log-analytics query --workspace {workspace_id} --analytics-query @{query_file}")
                
                if result:
                    results[nsg_id] = self._process_query_result(result)
                    self.logger.info(f"Query executed successfully for NSG {nsg_id}")
                else:
                    self.logger.warning(f"Query returned no results for NSG {nsg_id}")
            except Exception as e:
                self.logger.error(f"Error executing query for NSG {nsg_id}: {str(e)}")
        
        return results

    def _process_query_result(self, raw_result: List[Dict]) -> Dict:
        """Process and standardize query results"""
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

    def generate_excel_report(self, nsg_info, flow_configs, query_results):
        """Generate Excel report with analysis results"""
        try:
            # Create dataframe
            report_data = []
            
            for nsg_id, results in query_results.items():
                nsg_name = nsg_id.split('/')[-1]
                report_data.append({
                    "NSG Name": nsg_name,
                    "Total Flows": results.get('total_flows', 0),
                    "Inbound Traffic (MB)": results.get('inbound_bytes', 0) / 1024**2,
                    "Outbound Traffic (MB)": results.get('outbound_bytes', 0) / 1024**2,
                    "Open Ports Count": len(results.get('ports', set()))
                })
            
            # If no results, add empty row
            if not report_data:
                report_data.append({
                    "NSG Name": "No Data",
                    "Total Flows": 0,
                    "Inbound Traffic (MB)": 0,
                    "Outbound Traffic (MB)": 0,
                    "Open Ports Count": 0
                })
            
            df = pd.DataFrame(report_data)
            
            # Write to Excel file
            output_path = os.path.join(self.output_dir, f"report_{self.target_ip}.xlsx")
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Traffic Summary')
                
            self.logger.info(f"Report generated: {output_path}")
            ColorPrinter.print_success(f"Report generated: {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Failed to generate report: {str(e)}")
            ColorPrinter.print_error(f"Failed to generate report: {str(e)}")
            return None

    def full_analysis(self, time_range_hours: int = 24):
        """Execute complete analysis workflow"""
        try:
            # Input validation
            valid, error_msg = self._validate_input(time_range_hours)
            if not valid:
                self.logger.error(f"Invalid input: {error_msg}")
                ColorPrinter.print_error(f"Input validation failed: {error_msg}")
                return False
                
            # Phase 1: NSG Discovery
            self.logger.info("Starting NSG discovery phase")
            nsg_ids = self.find_associated_nsgs()
            
            if not nsg_ids:
                self.logger.warning("No NSGs found associated with target IP")
                ColorPrinter.print_warning("No NSGs found associated with target IP")
                return False

            # Phase 2: Flow Logs Configuration
            self.logger.info("Retrieving flow logs configuration")
            flow_configs = self.get_flow_logs_config(nsg_ids)
            
            if not flow_configs:
                self.logger.warning("No flow logs configuration found")
                ColorPrinter.print_warning("No flow logs configuration found")
                return False
            
            # Phase 3: Log Analytics Processing
            self.logger.info("Processing Log Analytics workspaces")
            workspace_map = self.get_workspace_mapping(flow_configs)
            
            if not workspace_map:
                self.logger.warning("No Log Analytics workspaces found with flow logs enabled")
                ColorPrinter.print_warning("No Log Analytics workspaces found with flow logs enabled")
                return False
                
            # Phase 4: Query Execution
            self.logger.info("Executing KQL queries")
            query_results = self.execute_queries(workspace_map, time_range_hours)
            
            if not query_results:
                self.logger.warning("No query results returned")
                ColorPrinter.print_warning("No query results returned")
                return False
            
            # Phase 5: Report Generation
            self.logger.info("Generating final report")
            report_path = self.generate_excel_report(
                nsg_info={"nsg_ids": nsg_ids},
                flow_configs=flow_configs,
                query_results=query_results
            )
            
            if report_path:
                ColorPrinter.print_success("Analysis completed successfully")
                return True
            else:
                return False

        except Exception as e:
            self.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
            ColorPrinter.print_error(f"Critical error: {str(e)}")
            return False


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
            ColorPrinter.print_error("Invalid IP address format")
            sys.exit(1)
            
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
    except Exception as e:
        ColorPrinter.print_error(f"Critical error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
