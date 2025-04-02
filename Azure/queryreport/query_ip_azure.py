#!/usr/bin/env python3
"""
query_ip_azure.py - Query Azure network traffic logs by IP address
Usage: python query_ip_azure.py <IP_address> [--days <number>]

This script finds resources associated with the specified IP address,
identifies relevant NSGs and their flow logs, and queries relevant
Log Analytics workspaces for network traffic data.

Examples:
  python query_ip_azure.py 10.0.0.1
  python query_ip_azure.py 192.168.1.100 --days 7
"""

import os
import sys
import json
import time
import datetime
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union

# Azure imports
try:
    from azure.identity import DefaultAzureCredential, AzureCliCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.loganalytics import LogAnalyticsManagementClient
    from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
except ImportError:
    print("Error: Required Azure packages are missing.")
    print("Please install them using: pip install azure-identity azure-mgmt-resource azure-mgmt-network azure-mgmt-monitor azure-mgmt-loganalytics")
    sys.exit(1)

# ANSI colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_color(text: str, color: str, bold: bool = False) -> None:
    """Print colored text to the console."""
    if bold:
        print(f"{Colors.BOLD}{color}{text}{Colors.RESET}")
    else:
        print(f"{color}{text}{Colors.RESET}")

def print_info(text: str) -> None:
    """Print informational message."""
    print_color(text, Colors.BLUE)

def print_success(text: str) -> None:
    """Print success message."""
    print_color(text, Colors.GREEN)

def print_warning(text: str) -> None:
    """Print warning message."""
    print_color(text, Colors.YELLOW)

def print_error(text: str) -> None:
    """Print error message."""
    print_color(text, Colors.RED)

def save_json(data: Union[List, Dict], file_path: str) -> None:
    """Save data to JSON file."""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Saved data to {file_path}")

def save_csv(data: List[Dict], file_path: str, headers: List[str]) -> None:
    """Save data to CSV file."""
    import csv
    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for item in data:
            row = [item.get(h.split(':')[0], '') for h in headers]
            writer.writerow(row)
    print(f"Saved CSV to {file_path}")

class AzureIPTrafficAnalyzer:
    """Azure IP Traffic Analyzer class for querying network traffic by IP."""
    
    def __init__(self, target_ip: str, days_back: int = 30):
        """
        Initialize the analyzer with target IP and time range.
        
        Args:
            target_ip: The IP address to analyze
            days_back: Number of days to look back for traffic data
        """
        self.target_ip = target_ip
        self.days_back = days_back
        
        # Calculate time range
        end_date = datetime.datetime.utcnow()
        start_date = end_date - datetime.timedelta(days=days_back)
        self.start_date = start_date.strftime('%Y-%m-%dT%H:%M:%SZ')
        self.end_date = end_date.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # Create output directory
        date_tag = time.strftime('%Y%m%d%H%M%S')
        self.output_dir = f"ip_traffic_{target_ip.replace('.', '_')}_{date_tag}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize Azure clients
        self.credential = None
        self.subscription_id = None
        self.resource_client = None
        self.network_client = None
        self.monitor_client = None
        self.loganalytics_client = None
        
        # Results containers
        self.associated_resources = []
        self.related_nsg_rules = []
        self.flow_logs = []
        self.target_workspaces = []
        self.all_network_traffic = []
        self.subnet_nsg_ids = []
        
        print_info("=" * 60)
        print_success("Azure IP Traffic Analyzer (Python)")
        print_info("=" * 60)
        print(f"Target IP: {Colors.YELLOW}{self.target_ip}{Colors.RESET}")
        print(f"Time Range: {Colors.YELLOW}{self.start_date}{Colors.RESET} to {Colors.YELLOW}{self.end_date}{Colors.RESET}")
        print(f"Output Directory: {Colors.YELLOW}{self.output_dir}{Colors.RESET}")
        print_info("=" * 60)

    def login_to_azure(self) -> bool:
        """
        Authenticate with Azure and retrieve current subscription.
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        print_info("\n[1/5] Checking Azure login status...")
        
        try:
            # Use subprocess to call az commands directly, similar to the shell script
            import subprocess
            import json
            import shutil
            import os
            
            # First check if az command is available
            az_path = shutil.which("az")
            if not az_path:
                print_error("Azure CLI (az command) not found in PATH")
                print("Please install Azure CLI by following these steps:")
                print("1. Visit: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
                print("2. Run the installer for Windows")
                print("3. Restart your terminal/command prompt")
                print("4. Try running 'az --version' to verify installation")
                return False
                
            print(f"Found Azure CLI at: {az_path}")
            
            # Check if already logged in
            try:
                # Run 'az account show' to check login status (using shell=True for Windows paths with spaces)
                result = subprocess.run(
                    "az account show --query id -o tsv",
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    self.subscription_id = result.stdout.strip()
                    print_success(f"Already logged in to Azure")
                    
                    # Get tenant ID
                    tenant_result = subprocess.run(
                        "az account show --query tenantId -o tsv",
                        shell=True,
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    tenant_id = tenant_result.stdout.strip() if tenant_result.returncode == 0 else "Unknown"
                    
                    print(f"Current Subscription: {Colors.YELLOW}{self.subscription_id}{Colors.RESET}")
                    print(f"Current Tenant: {Colors.YELLOW}{tenant_id}{Colors.RESET}")
                else:
                    print("Not logged in. Attempting to login to Azure...")
                    # Run 'az login'
                    login_result = subprocess.run(
                        "az login",
                        shell=True,
                        capture_output=False,  # Let the login process show its own output for browser opening
                        text=True,
                        check=False
                    )
                    
                    if login_result.returncode != 0:
                        print_error(f"Login failed")
                        return False
                    
                    # Get subscription ID
                    result = subprocess.run(
                        "az account show --query id -o tsv",
                        shell=True,
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        self.subscription_id = result.stdout.strip()
                        
                        # Get tenant ID
                        tenant_result = subprocess.run(
                            "az account show --query tenantId -o tsv",
                            shell=True,
                            capture_output=True,
                            text=True,
                            check=False
                        )
                        tenant_id = tenant_result.stdout.strip() if tenant_result.returncode == 0 else "Unknown"
                        
                        print_success(f"Successfully logged in to Azure")
                        print(f"Current Subscription: {Colors.YELLOW}{self.subscription_id}{Colors.RESET}")
                        print(f"Current Tenant: {Colors.YELLOW}{tenant_id}{Colors.RESET}")
                    else:
                        print_error("Failed to get subscription ID after login")
                        return False
                
                # Initialize Azure clients using AzureCliCredential
                # This will directly use the CLI's login session
                self.credential = AzureCliCredential()
                self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
                self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
                self.monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
                self.loganalytics_client = LogAnalyticsManagementClient(self.credential, self.subscription_id)
                
                return True
                
            except subprocess.SubprocessError as e:
                print_error(f"Error executing Azure CLI command: {str(e)}")
                return False
                
        except Exception as e:
            print_error(f"Unexpected error during authentication: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def find_resources_by_ip(self) -> None:
        """Find Azure resources associated with the target IP address and determine related NSG flow logs."""
        print_info(f"\n[2/5] 查找与IP {self.target_ip}相关的资源...")
        
        try:
            # 检查凭据是否正确设置
            if self.credential is None:
                print_error("Azure凭据未初始化，请先运行login_to_azure()")
                return
            
            # 找到与IP相关的所有NSG
            nsg_ids = self.get_nsgs_for_ip()
            
            # 如果找到NSG，直接进行流日志查询
            if nsg_ids:
                self.subnet_nsg_ids = nsg_ids
                self.find_flow_logs()
            else:
                print_warning(f"未找到与IP {self.target_ip}相关的NSG，无法查询流日志")
        
        except Exception as e:
            print_error(f"查找资源时出错: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def get_nsgs_for_ip(self) -> List[str]:
        """
        直接从IP地址获取相关的NSG IDs，使用多种方法。
        
        Returns:
            List[str]: NSG IDs列表
        """
        print_info(f"\n[2a/5] 专门查询与IP {self.target_ip}相关的NSG...")
        nsg_ids = []
        
        # 1. 首先尝试查询直接使用此IP的网络接口相关的NSG
        try:
            print_info("方法1: 查询拥有此IP的网络接口相关的NSG...")
            
            # 方法1.1: 使用Resource Graph
            try:
                from azure.mgmt.resourcegraph import ResourceGraphClient
                from azure.mgmt.resourcegraph.models import QueryRequest
                
                graph_client = ResourceGraphClient(self.credential)
                
                nic_query = f"""
                Resources
                | where type =~ 'microsoft.network/networkinterfaces'
                | where properties.ipConfigurations[0].properties.privateIPAddress =~ '{self.target_ip}'
                | project id, name, resourceGroup, location, 
                         nsgId = tostring(properties.networkSecurityGroup.id)
                """
                
                request = QueryRequest(query=nic_query, subscriptions=[self.subscription_id])
                response = graph_client.resources(request)
                
                if response.data:
                    print_success(f"找到{len(response.data)}个使用IP {self.target_ip}的网络接口")
                    for nic in response.data:
                        nsg_id = nic.get('nsgId')
                        if nsg_id and nsg_id not in nsg_ids:
                            nsg_ids.append(nsg_id)
                            print_success(f"从网络接口找到NSG: {nsg_id}")
                else:
                    print_warning(f"未找到使用IP {self.target_ip}的网络接口")
            except Exception as graph_error:
                print_warning(f"Resource Graph查询网络接口失败: {str(graph_error)}")
                
                # 方法1.2: 备选使用Azure CLI
                try:
                    print_info("备选方法: 使用Azure CLI查询网络接口...")
                    import subprocess
                    import json
                    
                    cmd = f"az network nic list --query \"[?ipConfigurations[0].privateIpAddress=='{self.target_ip}'].{{id:id, name:name, nsgId:networkSecurityGroup.id}}\" -o json"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        nics = json.loads(result.stdout)
                        print_success(f"使用CLI找到{len(nics)}个使用IP {self.target_ip}的网络接口")
                        
                        for nic in nics:
                            nsg_id = nic.get('nsgId')
                            if nsg_id and nsg_id not in nsg_ids:
                                nsg_ids.append(nsg_id)
                                print_success(f"从网络接口(CLI)找到NSG: {nsg_id}")
                    else:
                        print_warning(f"CLI未找到使用IP {self.target_ip}的网络接口")
                except Exception as cli_error:
                    print_warning(f"Azure CLI查询网络接口失败: {str(cli_error)}")
        except Exception as nic_error:
            print_warning(f"查询网络接口相关NSG失败: {str(nic_error)}")
            
        # 2. 查找包含此IP的子网及其关联的NSG
        if not nsg_ids:  # 如果还没有找到NSG，继续尝试查找子网
            try:
                print_info("\n方法2: 查找包含此IP的子网及关联的NSG...")
                
                # 2.1 查询所有VNET和子网
                try:
                    from azure.mgmt.resourcegraph import ResourceGraphClient
                    from azure.mgmt.resourcegraph.models import QueryRequest
                    
                    if not 'graph_client' in locals():
                        graph_client = ResourceGraphClient(self.credential)
                    
                    subnet_query = """
                    Resources
                    | where type =~ 'microsoft.network/virtualnetworks'
                    | mv-expand subnet=properties.subnets
                    | project vnetName=name, vnetId=id, 
                             resourceGroup=resourceGroup,
                             subnetName=subnet.name, 
                             subnetPrefix=subnet.properties.addressPrefix,
                             subnetId=subnet.id, 
                             nsgId=tostring(subnet.properties.networkSecurityGroup.id)
                    """
                    
                    request = QueryRequest(query=subnet_query, subscriptions=[self.subscription_id])
                    subnet_response = graph_client.resources(request)
                    
                    if subnet_response.data:
                        subnets = subnet_response.data
                        print_success(f"找到{len(subnets)}个子网，现在检查哪些包含IP {self.target_ip}")
                        save_json(subnets, os.path.join(self.output_dir, "all_subnets_detail.json"))
                        
                        # 转换IP为整数，用于子网范围检查
                        ip_parts = self.target_ip.split('.')
                        if len(ip_parts) != 4:
                            raise ValueError(f"无效的IP地址格式: {self.target_ip}")
                            
                        ip_int = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8) + int(ip_parts[3])
                        
                        # 检查IP是否在每个子网范围内
                        matching_subnets = []
                        
                        for subnet in subnets:
                            subnet_prefix = subnet.get('subnetPrefix')
                            
                            # 有些子网前缀可能是数组
                            prefixes = []
                            if isinstance(subnet_prefix, list):
                                prefixes.extend(subnet_prefix)
                            else:
                                prefixes.append(subnet_prefix)
                                
                            for prefix in prefixes:
                                if prefix and self._ip_in_subnet(ip_int, prefix):
                                    matching_subnets.append(subnet)
                                    print_success(f"IP {self.target_ip}在子网{subnet.get('subnetName')}的范围{prefix}内")
                                    
                                    # 获取子网关联的NSG
                                    nsg_id = subnet.get('nsgId')
                                    if nsg_id and nsg_id not in nsg_ids:
                                        nsg_ids.append(nsg_id)
                                        print_success(f"从子网{subnet.get('subnetName')}找到NSG: {nsg_id}")
                                    break
                        
                        # 保存匹配的子网
                        if matching_subnets:
                            save_json(matching_subnets, os.path.join(self.output_dir, "matching_subnets_detail.json"))
                        else:
                            print_warning(f"未找到包含IP {self.target_ip}的子网")
                            
                            # 2.2 尝试使用Azure CLI查找子网
                            if not nsg_ids:
                                try:
                                    self._find_subnets_with_cli()
                                except Exception as cli_subnet_error:
                                    print_warning(f"使用CLI查找子网失败: {str(cli_subnet_error)}")
                    else:
                        print_warning("未找到虚拟网络或子网信息")
                except Exception as subnet_error:
                    print_warning(f"查询子网信息失败: {str(subnet_error)}")
                    
                    # 备选方案：使用Azure CLI
                    try:
                        self._find_subnets_with_cli()
                    except Exception as cli_error:
                        print_warning(f"使用CLI查找子网失败: {str(cli_error)}")
            except Exception as subnet_process_error:
                print_warning(f"处理子网信息时出错: {str(subnet_process_error)}")
                
        # 3. 直接查询NSG，看是否有规则引用了此IP (不太推荐，因为NSG引用IP不代表流量会通过它)
        try:
            print_info("\n方法3: 查询直接引用此IP的NSG规则...")
            
            try:
                from azure.mgmt.resourcegraph import ResourceGraphClient
                from azure.mgmt.resourcegraph.models import QueryRequest
                
                if not 'graph_client' in locals():
                    graph_client = ResourceGraphClient(self.credential)
                
                nsg_query = f"""
                Resources
                | where type =~ 'microsoft.network/networksecuritygroups'
                | where properties.securityRules[*].properties.sourceAddressPrefix contains '{self.target_ip}'
                   or properties.securityRules[*].properties.destinationAddressPrefix contains '{self.target_ip}'
                | project id, name, resourceGroup, location
                """
                
                request = QueryRequest(query=nsg_query, subscriptions=[self.subscription_id])
                nsg_response = graph_client.resources(request)
                
                if nsg_response.data:
                    print_success(f"找到{len(nsg_response.data)}个直接引用IP {self.target_ip}的NSG")
                    for nsg in nsg_response.data:
                        nsg_id = nsg.get('id')
                        if nsg_id and nsg_id not in nsg_ids:
                            nsg_ids.append(nsg_id)
                            print_success(f"找到引用IP的NSG: {nsg_id}")
                else:
                    print_warning(f"未找到直接引用IP {self.target_ip}的NSG")
            except Exception as rule_error:
                print_warning(f"查询NSG规则失败: {str(rule_error)}")
        except Exception as nsg_rule_error:
            print_warning(f"查询引用IP的NSG规则失败: {str(nsg_rule_error)}")
        
        # 打印结果
        if nsg_ids:
            print_success(f"总共找到{len(nsg_ids)}个与IP {self.target_ip}相关的NSG")
            save_json(nsg_ids, os.path.join(self.output_dir, "related_nsg_ids.json"))
        else:
            print_warning(f"未找到与IP {self.target_ip}相关的NSG")
            
        return nsg_ids
            
    def _ip_in_subnet(self, ip_int: int, subnet_prefix: str) -> bool:
        """
        检查IP是否在给定的子网范围内。
        
        Args:
            ip_int: IP地址的整数表示
            subnet_prefix: 子网前缀，格式为"x.x.x.x/y"
            
        Returns:
            bool: 如果IP在子网范围内，返回True
        """
        try:
            # 解析子网前缀 (例如 "10.0.0.0/24")
            subnet_addr, subnet_mask = subnet_prefix.split('/')
            subnet_mask = int(subnet_mask)
            
            # 解析子网地址
            subnet_parts = subnet_addr.split('.')
            if len(subnet_parts) != 4:
                return False
                
            # 将子网转换为整数
            subnet_int = (int(subnet_parts[0]) << 24) + (int(subnet_parts[1]) << 16) + \
                         (int(subnet_parts[2]) << 8) + int(subnet_parts[3])
                         
            # 计算掩码
            mask_int = (0xFFFFFFFF << (32 - subnet_mask)) & 0xFFFFFFFF
            
            # 检查IP是否在子网范围内
            return (ip_int & mask_int) == (subnet_int & mask_int)
        except (ValueError, IndexError) as e:
            print_warning(f"解析子网前缀时出错: {subnet_prefix}, 错误: {str(e)}")
            return False
            
    def _find_subnets_with_cli(self) -> List[str]:
        """使用Azure CLI查找包含目标IP的子网。"""
        print_info(f"使用Azure CLI查询包含IP {self.target_ip}的子网...")
        nsg_ids = []
        
        import subprocess
        import json
        
        try:
            # 获取所有VNET
            cmd_vnets = "az network vnet list --query \"[].{id:id, name:name, resourceGroup:resourceGroup, subnets:subnets}\" -o json"
            vnet_result = subprocess.run(cmd_vnets, shell=True, capture_output=True, text=True, check=False)
            
            if vnet_result.returncode == 0 and vnet_result.stdout.strip():
                vnets = json.loads(vnet_result.stdout)
                print_success(f"找到{len(vnets)}个VNET")
                
                # 解析IP
                ip_parts = self.target_ip.split('.')
                if len(ip_parts) != 4:
                    print_error(f"无效的IP地址格式: {self.target_ip}")
                    return []
                
                ip_int = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8) + int(ip_parts[3])
                
                # 检查每个VNET的子网
                for vnet in vnets:
                    vnet_name = vnet.get('name')
                    resource_group = vnet.get('resourceGroup')
                    
                    # 获取VNET的详细子网信息
                    cmd_subnets = f"az network vnet subnet list --resource-group {resource_group} --vnet-name {vnet_name} -o json"
                    subnet_result = subprocess.run(cmd_subnets, shell=True, capture_output=True, text=True, check=False)
                    
                    if subnet_result.returncode == 0 and subnet_result.stdout.strip():
                        subnets = json.loads(subnet_result.stdout)
                        
                        for subnet in subnets:
                            subnet_name = subnet.get('name')
                            address_prefix = subnet.get('addressPrefix')
                            
                            # 检查IP是否在子网范围内
                            if address_prefix and self._ip_in_subnet(ip_int, address_prefix):
                                print_success(f"IP {self.target_ip}在VNET '{vnet_name}'的子网'{subnet_name}'范围'{address_prefix}'内")
                                
                                # 获取子网关联的NSG
                                nsg = subnet.get('networkSecurityGroup', {})
                                if nsg:
                                    nsg_id = nsg.get('id')
                                    if nsg_id and nsg_id not in nsg_ids:
                                        nsg_ids.append(nsg_id)
                                        print_success(f"从子网'{subnet_name}'找到NSG: {nsg_id}")
                                else:
                                    print_warning(f"子网'{subnet_name}'没有关联的NSG")
            else:
                print_warning("无法获取VNET列表")
                
            # 打印结果
            if nsg_ids:
                print_success(f"通过CLI找到{len(nsg_ids)}个与IP {self.target_ip}相关的NSG")
                # 更新现有的NSG ID列表
                for nsg_id in nsg_ids:
                    if nsg_id not in self.subnet_nsg_ids:
                        self.subnet_nsg_ids.append(nsg_id)
                save_json(self.subnet_nsg_ids, os.path.join(self.output_dir, "related_nsg_ids.json"))
                
            return nsg_ids
        except Exception as cli_error:
            print_error(f"使用CLI查询子网时出错: {str(cli_error)}")
            return []
    
    def find_flow_logs(self) -> None:
        """Find NSG flow logs for relevant NSGs."""
        print_info(f"\n[3/5] Finding NSG flow logs...")
        
        # Collect NSG IDs from both direct associations and related rules
        nsg_ids = []
        
        # Add NSGs from direct resource associations
        for resource in self.associated_resources:
            nsg_id = resource.get('nsgId')
            if nsg_id and nsg_id not in nsg_ids:
                nsg_ids.append(nsg_id)
                
        # Add NSGs from related rules
        for nsg in self.related_nsg_rules:
            nsg_id = nsg.get('id')
            if nsg_id and nsg_id not in nsg_ids:
                nsg_ids.append(nsg_id)
                
        # Add NSGs from subnets
        for nsg_id in self.subnet_nsg_ids:
            if nsg_id not in nsg_ids:
                nsg_ids.append(nsg_id)
                
        if not nsg_ids:
            print_warning("No related NSGs found to check for flow logs")
            return
            
        print_info(f"Checking flow logs for {len(nsg_ids)} NSGs...")
        
        try:
            # Find flow logs for each NSG
            for nsg_id in nsg_ids:
                # Extract resource group from NSG ID
                parts = nsg_id.split('/')
                if len(parts) < 5:
                    continue
                    
                resource_group = None
                for i, part in enumerate(parts):
                    if part.lower() == 'resourcegroups' and i+1 < len(parts):
                        resource_group = parts[i+1]
                        break
                        
                if not resource_group:
                    continue
                    
                # Get NSG name from ID
                nsg_name = parts[-1] if parts else None
                if not nsg_name:
                    continue
                    
                # Query for flow logs targeting this NSG
                try:
                    # Use Azure Resource Graph for more efficient querying
                    from azure.mgmt.resourcegraph import ResourceGraphClient
                    from azure.mgmt.resourcegraph.models import QueryRequest
                    
                    graph_client = ResourceGraphClient(self.credential)
                    
                    query = f"""
                    Resources
                    | where type =~ 'microsoft.network/networkwatchers/flowlogs'
                    | where properties.targetResourceId =~ '{nsg_id}'
                    | project id, name, resourceGroup, location, enabled=properties.enabled,
                              retentionPolicy=properties.retentionPolicy,
                              storageId=properties.storageId,
                              workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId
                    """
                    
                    request = QueryRequest(query=query, subscriptions=[self.subscription_id])
                    response = graph_client.resources(request)
                    
                    if response.data:
                        for flow_log in response.data:
                            self.flow_logs.append(flow_log)
                            
                            # Extract workspace ID if present
                            workspace_id = flow_log.get('workspaceId')
                            if workspace_id and workspace_id not in [w.get('id') for w in self.target_workspaces]:
                                # Get workspace details
                                workspace_parts = workspace_id.split('/')
                                if len(workspace_parts) < 9:
                                    continue
                                    
                                workspace_rg = None
                                for i, part in enumerate(workspace_parts):
                                    if part.lower() == 'resourcegroups' and i+1 < len(workspace_parts):
                                        workspace_rg = workspace_parts[i+1]
                                        break
                                        
                                workspace_name = workspace_parts[-1] if workspace_parts else None
                                
                                if workspace_rg and workspace_name:
                                    try:
                                        workspace = self.loganalytics_client.workspaces.get(workspace_rg, workspace_name)
                                        if workspace:
                                            # Add to target workspaces
                                            self.target_workspaces.append({
                                                'id': workspace_id,
                                                'name': workspace_name,
                                                'resourceGroup': workspace_rg,
                                                'customerId': workspace.customer_id
                                            })
                                    except HttpResponseError as e:
                                        print_warning(f"Could not access workspace {workspace_name}: {str(e)}")
                                    except Exception as e:
                                        print_warning(f"Error retrieving workspace details: {str(e)}")
                
                except Exception as e:
                    print_warning(f"Error querying flow logs for NSG {nsg_name}: {str(e)}")
            
            # Save flow logs data
            if self.flow_logs:
                save_json(self.flow_logs, os.path.join(self.output_dir, "nsg_flow_logs.json"))
                print_success(f"Found {len(self.flow_logs)} NSG flow logs")
                
                # Generate CSV for flow logs
                if self.flow_logs:
                    headers = ["id", "name", "resourceGroup", "location", "enabled", "workspaceId"]
                    save_csv(self.flow_logs, 
                             os.path.join(self.output_dir, "nsg_flow_logs.csv"),
                             headers)
            else:
                print_warning("No flow logs found for the relevant NSGs")
                
            # Save target workspaces
            if self.target_workspaces:
                save_json(self.target_workspaces, os.path.join(self.output_dir, "target_workspaces.json"))
                print_success(f"Found {len(self.target_workspaces)} target Log Analytics workspaces")
                
                headers = ["id", "name", "resourceGroup", "customerId"]
                save_csv(self.target_workspaces,
                         os.path.join(self.output_dir, "target_workspaces.csv"),
                         headers)
            else:
                print_warning("No Log Analytics workspaces found for the flow logs")
                
        except Exception as e:
            print_error(f"Error finding flow logs: {str(e)}")
            
    def query_traffic_data(self) -> None:
        """Query Log Analytics workspaces for traffic data related to the IP."""
        print_info(f"\n[4/5] Querying traffic data from Log Analytics workspaces...")
        
        if not self.target_workspaces:
            print_warning("No target workspaces to query")
            return
            
        print_info(f"Querying {len(self.target_workspaces)} workspaces for traffic data...")
        
        # Get SDK package for log analytics queries
        try:
            from azure.monitor.query import LogsQueryClient
            from azure.monitor.query import LogsQueryStatus
            from azure.core.exceptions import HttpResponseError
        except ImportError:
            print_error("Error: Required Azure package azure-monitor-query is missing.")
            print("Please install it using: pip install azure-monitor-query")
            return
            
        # Set up logs query client
        logs_client = LogsQueryClient(self.credential)
        
        try:
            all_traffic_records = []
            
            # Query each workspace for traffic data
            for workspace in self.target_workspaces:
                workspace_id = workspace.get('id')
                workspace_name = workspace.get('name')
                customer_id = workspace.get('customerId')
                
                if not customer_id:
                    print_warning(f"Missing customer ID for workspace {workspace_name}, skipping")
                    continue
                
                print_info(f"Querying workspace: {workspace_name}")
                
                # KQL query for traffic data
                query = f"""
                AzureNetworkAnalytics_CL
                | where TimeGenerated >= datetime('{self.start_date}') and TimeGenerated <= datetime('{self.end_date}')
                | where SrcIP_s == '{self.target_ip}' or DestIP_s == '{self.target_ip}'
                | project TimeGenerated, FlowStartTime_t, FlowEndTime_t, FlowType_s, 
                          SrcIP_s, SrcPort_d, DestIP_s, DestPort_d, 
                          L4Protocol_s, L7Protocol_s, NSGRule_s, NSGList_s,
                          FlowDirection_s, AllowedInFlows_d, AllowedOutFlows_d,
                          DeniedInFlows_d, DeniedOutFlows_d
                | order by TimeGenerated desc
                """
                
                try:
                    # Execute query
                    response = logs_client.query_workspace(
                        workspace_id=customer_id,
                        query=query,
                        timespan=(self.start_date, self.end_date)
                    )
                    
                    # Process results
                    if response.status == LogsQueryStatus.SUCCESS:
                        records = []
                        if response.tables:
                            for table in response.tables:
                                for row in table.rows:
                                    record = {}
                                    for col_idx, column in enumerate(table.columns):
                                        record[column.name] = row[col_idx]
                                    records.append(record)
                                    
                        # Add workspace details to each record
                        for record in records:
                            record['WorkspaceName'] = workspace_name
                            record['WorkspaceID'] = customer_id
                            
                        # Add to overall results
                        all_traffic_records.extend(records)
                        
                        print_success(f"Found {len(records)} traffic records in workspace {workspace_name}")
                    else:
                        print_warning(f"Query failed for workspace {workspace_name}: {response.status}")
                        
                except HttpResponseError as e:
                    print_warning(f"Error querying workspace {workspace_name}: {str(e)}")
                except Exception as e:
                    print_warning(f"Unexpected error querying workspace {workspace_name}: {str(e)}")
            
            # Save all traffic data
            self.all_network_traffic = all_traffic_records
            
            if self.all_network_traffic:
                save_json(self.all_network_traffic, os.path.join(self.output_dir, "network_traffic.json"))
                print_success(f"Found total of {len(self.all_network_traffic)} traffic records across all workspaces")
                
                # Generate CSV for traffic data
                if self.all_network_traffic and len(self.all_network_traffic) > 0:
                    # Use keys from first record to build headers
                    first_record = self.all_network_traffic[0]
                    headers = list(first_record.keys())
                    
                    save_csv(self.all_network_traffic,
                             os.path.join(self.output_dir, "network_traffic.csv"),
                             headers)
            else:
                print_warning(f"No traffic data found for IP {self.target_ip} in the specified time range")
                
        except Exception as e:
            print_error(f"Error querying traffic data: {str(e)}")

    def generate_report(self) -> None:
        """Generate a summary report of findings."""
        print_info(f"\n[5/5] Generating summary report...")
        
        # Create report file
        report_file = os.path.join(self.output_dir, "summary_report.md")
        
        with open(report_file, 'w') as f:
            f.write(f"# Azure IP Traffic Analysis Report\n\n")
            f.write(f"## Summary\n\n")
            f.write(f"- **Target IP:** {self.target_ip}\n")
            f.write(f"- **Time Range:** {self.start_date} to {self.end_date}\n")
            f.write(f"- **Report Generated:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            
            f.write(f"## Associated Resources\n\n")
            if self.associated_resources:
                f.write(f"Found {len(self.associated_resources)} resources with IP {self.target_ip}\n\n")
                f.write("| Resource Name | Resource Group | Location | NSG ID |\n")
                f.write("|--------------|---------------|----------|--------|\n")
                
                for resource in self.associated_resources:
                    name = resource.get('name', 'N/A')
                    rg = resource.get('resourceGroup', 'N/A')
                    location = resource.get('location', 'N/A')
                    nsg_id = resource.get('nsgId', 'N/A')
                    nsg_name = nsg_id.split('/')[-1] if nsg_id else 'N/A'
                    
                    f.write(f"| {name} | {rg} | {location} | {nsg_name} |\n")
            else:
                f.write("No resources directly associated with this IP address were found.\n\n")
                
            f.write(f"\n## Related NSG Rules\n\n")
            if self.related_nsg_rules:
                f.write(f"Found {len(self.related_nsg_rules)} NSGs with rules referencing IP {self.target_ip}\n\n")
                f.write("| NSG Name | Resource Group | Location |\n")
                f.write("|----------|---------------|----------|\n")
                
                for nsg in self.related_nsg_rules:
                    name = nsg.get('name', 'N/A')
                    rg = nsg.get('resourceGroup', 'N/A')
                    location = nsg.get('location', 'N/A')
                    
                    f.write(f"| {name} | {rg} | {location} |\n")
            else:
                f.write("No NSGs with rules referencing this IP address were found.\n\n")
                
            f.write(f"\n## NSG Flow Logs\n\n")
            if self.flow_logs:
                f.write(f"Found {len(self.flow_logs)} flow logs for relevant NSGs\n\n")
                f.write("| Flow Log Name | Resource Group | Enabled | Workspace |\n")
                f.write("|--------------|---------------|---------|----------|\n")
                
                for flow_log in self.flow_logs:
                    name = flow_log.get('name', 'N/A')
                    rg = flow_log.get('resourceGroup', 'N/A')
                    enabled = flow_log.get('enabled', 'N/A')
                    workspace_id = flow_log.get('workspaceId', 'N/A')
                    workspace_name = workspace_id.split('/')[-1] if workspace_id else 'N/A'
                    
                    f.write(f"| {name} | {rg} | {enabled} | {workspace_name} |\n")
            else:
                f.write("No flow logs were found for the relevant NSGs.\n\n")
                
            f.write(f"\n## Traffic Data\n\n")
            if self.all_network_traffic:
                f.write(f"Found {len(self.all_network_traffic)} traffic records across all workspaces\n\n")
                
                # Group by source and destination
                sources = {}
                destinations = {}
                protocols = {}
                allowed = 0
                denied = 0
                
                for record in self.all_network_traffic:
                    # Count sources
                    src_ip = record.get('SrcIP_s')
                    if src_ip:
                        sources[src_ip] = sources.get(src_ip, 0) + 1
                        
                    # Count destinations
                    dst_ip = record.get('DestIP_s')
                    if dst_ip:
                        destinations[dst_ip] = destinations.get(dst_ip, 0) + 1
                        
                    # Count protocols
                    protocol = record.get('L4Protocol_s')
                    if protocol:
                        protocols[protocol] = protocols.get(protocol, 0) + 1
                        
                    # Count allowed vs denied
                    flow_type = record.get('FlowType_s', '').lower()
                    if 'allowed' in flow_type:
                        allowed += 1
                    elif 'denied' in flow_type:
                        denied += 1
                
                # Top sources
                f.write("### Top Source IPs\n\n")
                f.write("| IP Address | Count |\n")
                f.write("|------------|-------|\n")
                
                for ip, count in sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"| {ip} | {count} |\n")
                    
                # Top destinations
                f.write("\n### Top Destination IPs\n\n")
                f.write("| IP Address | Count |\n")
                f.write("|------------|-------|\n")
                
                for ip, count in sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"| {ip} | {count} |\n")
                    
                # Protocols
                f.write("\n### Protocols\n\n")
                f.write("| Protocol | Count |\n")
                f.write("|----------|-------|\n")
                
                for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"| {protocol} | {count} |\n")
                    
                # Allowed vs Denied
                f.write("\n### Traffic Summary\n\n")
                f.write(f"- **Allowed Flows:** {allowed}\n")
                f.write(f"- **Denied Flows:** {denied}\n")
                f.write(f"- **Total Flows:** {len(self.all_network_traffic)}\n")
                
            else:
                f.write("No traffic data was found for this IP address in the specified time range.\n\n")
                
            f.write(f"\n## Conclusion\n\n")
            f.write(f"This report provides an analysis of network traffic and Azure resources related to IP {self.target_ip} ")
            f.write(f"for the period from {self.start_date} to {self.end_date}.\n\n")
            f.write(f"For more detailed information, please refer to the JSON and CSV files in the output directory: {self.output_dir}\n")
            
        print_success(f"Summary report generated: {report_file}")
        
    def run(self) -> None:
        """Run the complete analysis workflow."""
        if not self.login_to_azure():
            return
            
        self.find_resources_by_ip()
        self.find_flow_logs()
        self.query_traffic_data()
        self.generate_report()
        
        print_success(f"\nAnalysis complete! Results saved to: {self.output_dir}")
        print(f"Summary report: {os.path.join(self.output_dir, 'summary_report.md')}")

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Query Azure network traffic logs by IP address',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python query_ip_azure.py 10.0.0.1
  python query_ip_azure.py 192.168.1.100 --days 7
        """
    )
    parser.add_argument('ip_address', help='The IP address to query for')
    parser.add_argument('--days', type=int, default=30, help='Number of days to look back (default: 30)')
    
    args = parser.parse_args()
    
    analyzer = AzureIPTrafficAnalyzer(args.ip_address, args.days)
    analyzer.run()

if __name__ == "__main__":
    main()
