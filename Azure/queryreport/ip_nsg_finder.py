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
from datetime import datetime
from typing import List, Dict, Any, Optional

# Import required modules
import argparse
import sys
from .utils.logger import setup_logger, ColorPrinter
from .utils.azure_cli import run_az_command, check_az_login
from .models.nsg import NSGAnalyzer
from .models.flow_logs import FlowLogsManager
from .reports.excel import generate_excel_report
from .exceptions import InvalidIPError, AzureCLIError

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

    def full_analysis(self, time_range_hours: int = 24):
        """Execute complete analysis workflow"""
        try:
            # 输入验证
            self._validate_input(time_range_hours)
            # Phase 1: NSG Discovery
            self.logger.info("Starting NSG discovery phase")
            nsg_ids = self.nsg_analyzer.find_associated_nsgs()
            
            if not nsg_ids:
                ColorPrinter.print_warning("No NSGs found associated with target IP")
                return

            # Phase 2: Flow Logs Configuration
            self.logger.info("Retrieving flow logs configuration")
            flow_configs = self.flow_logs_manager.get_configurations(nsg_ids)
            
            # Phase 3: Log Analytics Processing
            self.logger.info("Processing Log Analytics workspaces")
            workspace_map = self.flow_logs_manager.get_workspace_mapping(flow_configs)
            
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

        except ValueError as ve:
            self.logger.error(f"Invalid input: {str(ve)}")
            ColorPrinter.print_error(f"Input validation failed: {str(ve)}")
        except subprocess.CalledProcessError as cpe:
            self.logger.error(f"Azure CLI command failed: {cpe.stderr}")
            ColorPrinter.print_error(f"Azure CLI错误: {cpe.output}")
        except Exception as e:
            self.logger.error(f"未处理异常: {str(e)}", exc_info=True)
            ColorPrinter.print_error(f"严重错误: {str(e)}")

    def _execute_queries(self, workspace_map: Dict[str, str],
                        time_range_hours: int) -> Dict[str, Any]:
        """Execute KQL queries against identified workspaces"""
        results = {}
        query_generator = KQLQueryBuilder(self.target_ip, time_range_hours)
        
        for nsg_id, workspace_id in workspace_map.items():
            try:
                query = query_generator.build_traffic_analysis_query()
                result = run_az_command(
                    f"az monitor log-analytics query --workspace {workspace_id} "
                    f"--analytics-query @{query_generator.save_temp_query()} -o json")
                
                if result:
                    results[nsg_id] = self._process_query_result(result)
                    
            except Exception as e:
                self.logger.error(f"Query failed for NSG {nsg_id}: {str(e)}")
                
        return results

    def _process_query_result(self, raw_result: Dict) -> Dict:
        """Process and standardize query results"""
        # Implement result normalization logic
        return raw_result

class KQLQueryBuilder:
    """Build and manage KQL queries"""
    
    def __init__(self, target_ip: str, time_range_hours: int):
        self.target_ip = target_ip
        self.time_range = time_range_hours
        self.temp_dir = "temp_queries"
        os.makedirs(self.temp_dir, exist_ok=True)

    def build_traffic_analysis_query(self) -> str:
        """Construct main traffic analysis query"""
        return f"""
        AzureNetworkAnalytics_CL
        | where TimeGenerated >= ago({self.time_range}h)
        | where SrcIP_s == '{self.target_ip}' or DestIP_s == '{self.target_ip}'
        | project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, Protocol_s,
                  NSG_s, Subnet_s, Action_s, FlowStatus_s
        | sort by TimeGenerated desc
        """

    def save_temp_query(self) -> str:
        """Save query to temporary file"""
        temp_path = os.path.join(self.temp_dir, f"query_{self.target_ip}.kql")
        with open(temp_path, 'w') as f:
            f.write(self.build_traffic_analysis_query())
        return temp_path

def main():
    """Main entry point function"""
    parser = argparse.ArgumentParser(
        description="Find associated Azure NSGs and analyze traffic logs by IP address",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument("ip_address",
        help="Target IP address to analyze (IPv4/IPv6)")
    parser.add_argument("--time-range", type=int, default=24,
        help="查询日志的时间范围（小时）")
    parser.add_argument("--verbose", action="store_true",
        help="启用详细日志输出")
    
    args = parser.parse_args()
    
    try:
        # 初始化日志系统
        log_level = logging.DEBUG if args.verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("nsg_analysis.log"),
                logging.StreamHandler()
            ])
        
        # IP地址格式验证（含时区处理）
        try:
            ipaddress.ip_address(args.ip_address)
            # 转换时间为UTC时区
            os.environ['TZ'] = 'UTC'
            time.tzset()
        except ValueError:
            ColorPrinter.print_error("Invalid IP address format")
            sys.exit(1)
            
        # 检查Azure CLI登录状态
        check_az_login()
        
        # 执行分析
        analyzer = NSGTrafficAnalyzer(args.ip_address)
        analyzer.full_analysis(args.time_range)
        
    except KeyboardInterrupt:
        ColorPrinter.print_warning("Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        ColorPrinter.print_error(f"严重错误: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
