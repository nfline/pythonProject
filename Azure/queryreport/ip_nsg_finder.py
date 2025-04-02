#!/usr/bin/env python3
"""
ip_nsg_finder.py - Find NSGs associated with an IP address

Usage: python ip_nsg_finder.py <IP_address>

This script finds NSGs associated with a specified IP address,
allowing for subsequent traffic log queries.
"""

import os
import sys
import json
import argparse
import subprocess
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

# Terminal output colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_info(text: str) -> None:
    """Print informational message"""
    print(f"{Colors.BLUE}{text}{Colors.RESET}")

def print_success(text: str) -> None:
    """Print success message"""
    print(f"{Colors.GREEN}{text}{Colors.RESET}")

def print_warning(text: str) -> None:
    """Print warning message"""
    print(f"{Colors.YELLOW}{text}{Colors.RESET}")

def print_error(text: str) -> None:
    """Print error message"""
    print(f"{Colors.RED}{text}{Colors.RESET}")

def save_json(data: Any, file_path: str) -> None:
    """Save data to JSON file"""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)
    print_info(f"保存数据到 {file_path}")

def run_command(cmd: str) -> Optional[Dict]:
    """Run command and return JSON result"""
    try:
        print_info(f"执行命令: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            print_error(f"命令执行失败: {result.stderr}")
            return None
            
        if not result.stdout.strip():
            print_warning("命令执行成功但没有输出")
            return None
            
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            # Response might not be in JSON format
            print_info(f"命令输出: {result.stdout}")
            return {"raw_output": result.stdout.strip()}
    except Exception as e:
        print_error(f"运行命令时出错: {str(e)}")
        return None

def ip_in_subnet(ip_address: str, subnet_prefix: str) -> bool:
    """Check if IP is within subnet range using ipaddress module"""
    try:
        network = ipaddress.ip_network(subnet_prefix, strict=False)
        ip = ipaddress.ip_address(ip_address)
        return ip in network
    except ValueError as e:
        print_warning(f"解析IP或子网前缀时出错: {str(e)}")
        return False

def find_nsgs_by_ip(target_ip: str) -> List[str]:
    """Find list of NSG IDs associated with an IP"""
    print_info(f"\n查找与IP {target_ip}关联的NSG...")
    nsg_ids = []
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Find network interfaces directly using this IP
    print_info("\n步骤1: 查找直接使用该IP的网络接口...")
    nic_cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/networkinterfaces' | where properties.ipConfigurations[0].properties.privateIPAddress =~ '{target_ip}' | project id, name, resourceGroup, vnetId = tostring(properties.ipConfigurations[0].properties.subnet.id), nsgId = tostring(properties.networkSecurityGroup.id)\" --query \"data\" -o json"
    
    nics = run_command(nic_cmd)
    if nics:
        save_json(nics, os.path.join(output_dir, "network_interfaces.json"))
        print_success(f"找到{len(nics)}个使用IP {target_ip}的网络接口")
        
        # 1.1 Collect NSGs directly associated with NICs
        for nic in nics:
            nsg_id = nic.get('nsgId')
            if nsg_id and nsg_id not in nsg_ids:
                nsg_ids.append(nsg_id)
                print_success(f"从网络接口找到NSG: {nsg_id}")
        
        # 1.2 Get subnet IDs from network interfaces
        subnet_ids = []
        for nic in nics:
            subnet_id = nic.get('vnetId')
            if subnet_id and subnet_id not in subnet_ids:
                subnet_ids.append(subnet_id)
                print_success(f"找到子网ID: {subnet_id}")
                
                # Extract VNET name and subnet name from subnet ID
                parts = subnet_id.split('/')
                resource_group = None
                vnet_name = None 
                subnet_name = None
                
                for i, part in enumerate(parts):
                    if part.lower() == 'resourcegroups' and i+1 < len(parts):
                        resource_group = parts[i+1]
                    elif part.lower() == 'virtualnetworks' and i+1 < len(parts):
                        vnet_name = parts[i+1]
                    elif part.lower() == 'subnets' and i+1 < len(parts):
                        subnet_name = parts[i+1]
                
                if resource_group and vnet_name and subnet_name:
                    print_info(f"子网信息解析: 资源组={resource_group}, VNET={vnet_name}, 子网={subnet_name}")
                    
                    # 2. Get detailed subnet information directly from Azure
                    print_info(f"\n步骤2: 获取子网 {subnet_name} 的详细信息...")
                    subnet_cmd = f"az network vnet subnet show --resource-group {resource_group} --vnet-name {vnet_name} --name {subnet_name} -o json"
                    subnet_details = run_command(subnet_cmd)
                    
                    if subnet_details:
                        save_json(subnet_details, os.path.join(output_dir, f"subnet_{subnet_name}.json"))
                        
                        # Extract NSG associated with the subnet
                        subnet_nsg = subnet_details.get('networkSecurityGroup', {})
                        if isinstance(subnet_nsg, dict) and 'id' in subnet_nsg:
                            subnet_nsg_id = subnet_nsg['id']
                            if subnet_nsg_id and subnet_nsg_id not in nsg_ids:
                                nsg_ids.append(subnet_nsg_id)
                                print_success(f"从子网{subnet_name}找到NSG: {subnet_nsg_id}")
    else:
        print_warning(f"未找到使用IP {target_ip}的网络接口")
        
        # 3. If no network interfaces found, try to find subnets containing this IP
        print_info("\n步骤3: 查找包含IP的子网...")
        
        # 3.1 Query all subnets
        subnets_cmd = "az graph query -q \"Resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand subnet=properties.subnets | project vnetName=name, vnetId=id, resourceGroup=resourceGroup, subnetName=subnet.name, subnetPrefix=subnet.properties.addressPrefix, subnetId=subnet.id, nsgId=tostring(subnet.properties.networkSecurityGroup.id)\" --query \"data\" -o json"
        
        all_subnets = run_command(subnets_cmd)
        if all_subnets:
            save_json(all_subnets, os.path.join(output_dir, "all_subnets.json"))
            print_success(f"找到{len(all_subnets)}个子网")
            
            # Check each subnet to see if it contains this IP
            for subnet in all_subnets:
                subnet_prefix = subnet.get('subnetPrefix')
                
                # Subnet prefix could be string or list
                prefixes = []
                if isinstance(subnet_prefix, list):
                    prefixes.extend(subnet_prefix)
                elif subnet_prefix:
                    prefixes.append(subnet_prefix)
                
                for prefix in prefixes:
                    if prefix and ip_in_subnet(target_ip, prefix):
                        print_success(f"IP {target_ip}在子网{subnet.get('subnetName')}的范围{prefix}内")
                        
                        # Get NSG associated with the subnet
                        nsg_id = subnet.get('nsgId')
                        if nsg_id and nsg_id not in nsg_ids:
                            nsg_ids.append(nsg_id)
                            print_success(f"从子网{subnet.get('subnetName')}找到NSG: {nsg_id}")
                        else:
                            print_warning(f"子网{subnet.get('subnetName')}没有关联的NSG或NSG已经记录")
                        
                        # Get more subnet details
                        resource_group = subnet.get('resourceGroup')
                        vnet_name = subnet.get('vnetName')
                        subnet_name = subnet.get('subnetName')
                        
                        if resource_group and vnet_name and subnet_name:
                            subnet_cmd = f"az network vnet subnet show --resource-group {resource_group} --vnet-name {vnet_name} --name {subnet_name} -o json"
                            subnet_details = run_command(subnet_cmd)
                            
                            if subnet_details:
                                save_json(subnet_details, os.path.join(output_dir, f"subnet_{subnet_name}.json"))
        else:
            print_warning("无法获取子网列表")
    
    # Save all NSG IDs found
    if nsg_ids:
        save_json(nsg_ids, os.path.join(output_dir, "nsg_ids.json"))
        print_success(f"\n总共找到{len(nsg_ids)}个与IP {target_ip}相关的NSG:")
        for i, nsg_id in enumerate(nsg_ids):
            print(f"  {i+1}. {nsg_id}")
    else:
        print_warning(f"\n未找到与IP {target_ip}相关的NSG")
    
    return nsg_ids

def get_nsg_flow_logs_config(nsg_ids: List[str]) -> Dict[str, Dict]:
    """Get flow logs configuration for NSGs"""
    print_info("\n步骤4: 获取NSG流日志配置...")
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    flow_logs_config = {}
    
    for nsg_id in nsg_ids:
        # Extract resource group and NSG name from NSG ID
        parts = nsg_id.split('/')
        resource_group = None
        nsg_name = None
        
        for i, part in enumerate(parts):
            if part.lower() == 'resourcegroups' and i+1 < len(parts):
                resource_group = parts[i+1]
            elif part.lower() == 'networksecuritygroups' and i+1 < len(parts):
                nsg_name = parts[i+1]
        
        if not resource_group or not nsg_name:
            print_warning(f"无法从NSG ID中提取资源组和NSG名称: {nsg_id}")
            continue
            
        print_info(f"获取NSG {nsg_name} 的流日志配置...")
        
        # Query flow logs configuration via Azure CLI
        flow_logs_cmd = f"az network watcher flow-log list --resource-group {resource_group} --query \"[?contains(targetResourceId, '{nsg_id}')]\" -o json"
        flow_logs = run_command(flow_logs_cmd)
        
        if not flow_logs:
            # Alternative method using Resource Graph
            print_info(f"尝试使用Resource Graph查询NSG {nsg_name} 的流日志配置...")
            flow_logs_cmd = f"az graph query -q \"Resources | where type =~ 'Microsoft.Network/networkWatchers/flowLogs' | where properties.targetResourceId =~ '{nsg_id}' | project id, name, resourceGroup, flowLogResourceId=id, workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, workspaceRegion=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceRegion, enabled=properties.enabled, retentionPolicy=properties.retentionPolicy\" --query \"data\" -o json"
            flow_logs = run_command(flow_logs_cmd)
        
        if flow_logs:
            if isinstance(flow_logs, list):
                if len(flow_logs) > 0:
                    print_success(f"找到NSG {nsg_name} 的流日志配置")
                    flow_logs_config[nsg_id] = flow_logs[0]
                    save_json(flow_logs, os.path.join(output_dir, f"flow_logs_{nsg_name}.json"))
                else:
                    print_warning(f"NSG {nsg_name} 未配置流日志")
            else:
                print_success(f"找到NSG {nsg_name} 的流日志配置")
                flow_logs_config[nsg_id] = flow_logs
                save_json(flow_logs, os.path.join(output_dir, f"flow_logs_{nsg_name}.json"))
        else:
            print_warning(f"无法获取NSG {nsg_name} 的流日志配置")
    
    # Save all flow logs configurations
    if flow_logs_config:
        save_json(flow_logs_config, os.path.join(output_dir, "flow_logs_config.json"))
        print_success(f"保存了 {len(flow_logs_config)} 个NSG的流日志配置")
    else:
        print_warning("未找到任何NSG流日志配置")
    
    return flow_logs_config

def get_log_analytics_workspaces(flow_logs_config: Dict[str, Dict]) -> Dict[str, str]:
    """Extract Log Analytics workspace IDs from flow logs configuration"""
    print_info("\n步骤5: 提取Log Analytics工作区信息...")
    workspace_ids = {}
    
    for nsg_id, config in flow_logs_config.items():
        workspace_id = None
        
        # Try different paths to find workspace ID
        if isinstance(config, dict):
            if 'workspaceId' in config:
                workspace_id = config['workspaceId']
            elif 'flowAnalyticsConfiguration' in config.get('properties', {}):
                analytics_config = config['properties']['flowAnalyticsConfiguration']
                if isinstance(analytics_config, dict) and 'networkWatcherFlowAnalyticsConfiguration' in analytics_config:
                    flow_analytics = analytics_config['networkWatcherFlowAnalyticsConfiguration']
                    if isinstance(flow_analytics, dict) and 'workspaceId' in flow_analytics:
                        workspace_id = flow_analytics['workspaceId']
            elif 'properties' in config and 'flowAnalytics' in config['properties']:
                flow_analytics = config['properties']['flowAnalytics']
                if isinstance(flow_analytics, dict) and 'workspaceId' in flow_analytics:
                    workspace_id = flow_analytics['workspaceId']
        
        if workspace_id:
            nsg_name = nsg_id.split('/')[-1]
            workspace_ids[nsg_id] = workspace_id
            print_success(f"NSG {nsg_name} 的Log Analytics工作区ID: {workspace_id}")
    
    # Save workspace IDs
    if workspace_ids:
        output_dir = "output"
        save_json(workspace_ids, os.path.join(output_dir, "workspace_ids.json"))
        print_success(f"找到 {len(workspace_ids)} 个Log Analytics工作区ID")
    else:
        print_warning("未找到任何Log Analytics工作区ID")
    
    return workspace_ids

def generate_kql_query(target_ip: str, 
                      flow_logs_config: Dict[str, Dict], 
                      workspace_ids: Dict[str, str],
                      time_range_hours: int = 24) -> Dict[str, str]:
    """Generate KQL queries for each workspace"""
    print_info("\n步骤6: 生成KQL查询...")
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    kql_queries = {}
    
    # Get current time and time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=time_range_hours)
    
    # Format times for KQL query
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    # Create a mapping of workspace ID to NSG IDs
    workspace_to_nsgs = {}
    for nsg_id, workspace_id in workspace_ids.items():
        if workspace_id not in workspace_to_nsgs:
            workspace_to_nsgs[workspace_id] = []
        workspace_to_nsgs[workspace_id].append(nsg_id)
    
    # Generate KQL query for each workspace
    for workspace_id, nsg_ids in workspace_to_nsgs.items():
        # Create NSG filter condition
        nsg_names = []
        for nsg_id in nsg_ids:
            nsg_name = nsg_id.split('/')[-1]
            nsg_names.append(nsg_name)
        
        nsg_filter = " or ".join([f"NSGName_s == \"{name}\"" for name in nsg_names])
        
        # Basic KQL query for NSG flow logs
        query = f"""
AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where FlowType_s == "Flow" 
| where ({nsg_filter})
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
| project TimeGenerated, 
          NSGName_s, 
          FlowDirection_s, 
          SrcIP_s, 
          DestIP_s, 
          SrcPort_d, 
          DestPort_d, 
          Protocol_s, 
          FlowStatus_s,
          L7Protocol_s,
          AllowedInFlows_d,
          AllowedOutFlows_d,
          DeniedInFlows_d,
          DeniedOutFlows_d
| sort by TimeGenerated desc
"""
        
        # Create a short name for the workspace for filename
        workspace_short_id = workspace_id.split('/')[-1]
        
        # Save the query to a file
        query_filename = f"kql_query_{workspace_short_id}.kql"
        query_path = os.path.join(output_dir, query_filename)
        
        with open(query_path, 'w') as f:
            f.write(query)
        
        print_success(f"已生成KQL查询并保存到 {query_path}")
        
        # Add query to return dictionary
        kql_queries[workspace_id] = query
    
    # Save all queries
    if kql_queries:
        save_json({k: v for k, v in kql_queries.items()}, os.path.join(output_dir, "kql_queries.json"))
        print_success(f"总共生成了 {len(kql_queries)} 个KQL查询")
    else:
        print_warning("未能生成任何KQL查询")
    
    return kql_queries

def execute_kql_query(workspace_id: str, kql_query: str) -> Optional[Dict]:
    """Execute a KQL query against a Log Analytics workspace"""
    print_info(f"\n执行KQL查询，目标工作区: {workspace_id}")
    
    # Construct Azure CLI command to run the query
    cmd = f"az monitor log-analytics query --workspace {workspace_id} --analytics-query \"{kql_query}\" -o json"
    
    # Execute the query
    results = run_command(cmd)
    
    if results:
        # Save results
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        
        workspace_short_id = workspace_id.split('/')[-1]
        result_path = os.path.join(output_dir, f"query_results_{workspace_short_id}.json")
        
        save_json(results, result_path)
        print_success(f"查询结果已保存到 {result_path}")
        
        # Print summary
        if isinstance(results, list):
            print_success(f"查询返回了 {len(results)} 条记录")
            if len(results) > 0:
                print_info("记录示例:")
                for i, record in enumerate(results[:3]):  # Show up to 3 records
                    print(json.dumps(record, indent=2))
                    if i < len(results[:3]) - 1:
                        print("---")
        else:
            print_success("查询已执行，但返回数据结构不是预期的列表格式")
    else:
        print_warning("执行KQL查询失败或无结果")
    
    return results

def analyze_traffic(target_ip: str, time_range_hours: int = 24) -> Dict[str, Any]:
    """Main function to analyze traffic for an IP address"""
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    results = {
        "target_ip": target_ip,
        "time_range_hours": time_range_hours,
        "timestamp": datetime.utcnow().isoformat(),
        "nsg_ids": [],
        "workspaces": {},
        "kql_results": {}
    }
    
    # Step 1: Find NSGs associated with the IP
    print_info("\n====== 第1阶段: 查找相关的NSG ======")
    nsg_ids = find_nsgs_by_ip(target_ip)
    results["nsg_ids"] = nsg_ids
    
    if not nsg_ids:
        print_warning("未找到与IP相关的NSG，无法继续")
        save_json(results, os.path.join(output_dir, "analysis_results.json"))
        return results
    
    # Step 2: Get NSG flow logs configuration
    print_info("\n====== 第2阶段: 获取流日志配置 ======")
    flow_logs_config = get_nsg_flow_logs_config(nsg_ids)
    results["flow_logs_config"] = flow_logs_config
    
    if not flow_logs_config:
        print_warning("未找到任何NSG流日志配置，无法继续")
        save_json(results, os.path.join(output_dir, "analysis_results.json"))
        return results
    
    # Step 3: Extract Log Analytics workspace IDs
    print_info("\n====== 第3阶段: 提取工作区信息 ======")
    workspace_ids = get_log_analytics_workspaces(flow_logs_config)
    results["workspaces"] = workspace_ids
    
    if not workspace_ids:
        print_warning("未找到任何Log Analytics工作区ID，无法继续")
        save_json(results, os.path.join(output_dir, "analysis_results.json"))
        return results
    
    # Step 4: Generate KQL queries
    print_info("\n====== 第4阶段: 生成KQL查询 ======")
    kql_queries = generate_kql_query(target_ip, flow_logs_config, workspace_ids, time_range_hours)
    results["kql_queries"] = kql_queries
    
    if not kql_queries:
        print_warning("无法生成KQL查询，无法继续")
        save_json(results, os.path.join(output_dir, "analysis_results.json"))
        return results
    
    # Step 5: Execute KQL queries (optional)
    should_execute = input("\n是否执行KQL查询？(y/n): ").lower().strip() == 'y'
    if should_execute:
        print_info("\n====== 第5阶段: 执行KQL查询 ======")
        for workspace_id, query in kql_queries.items():
            query_results = execute_kql_query(workspace_id, query)
            results["kql_results"][workspace_id] = query_results
    
    # Save final results
    save_json(results, os.path.join(output_dir, "analysis_results.json"))
    
    return results

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Find NSGs associated with an IP address and analyze traffic')
    parser.add_argument('ip_address', help='The IP address to query')
    parser.add_argument('--time-range', type=int, default=24, help='Time range in hours for traffic analysis (default: 24)')
    parser.add_argument('--analyze', action='store_true', help='Perform full traffic analysis including KQL query generation')
    
    args = parser.parse_args()
    
    print_info("=" * 60)
    print_success(f"IP NSG 分析器")
    print_info("=" * 60)
    print(f"目标IP: {args.ip_address}")
    print(f"时间范围: {args.time_range} 小时")
    print_info("=" * 60)
    
    if args.analyze:
        # Perform full analysis
        analyze_traffic(args.ip_address, args.time_range)
    else:
        # Just find NSGs
        nsg_ids = find_nsgs_by_ip(args.ip_address)
        
        # Validate NSGs found
        if nsg_ids:
            print_success("\n查找完成！已找到相关NSG。")
            print_info("如需执行完整的流量分析，请使用 --analyze 参数运行脚本")
        else:
            print_warning("\n查找完成，但未找到相关NSG。")
    
if __name__ == "__main__":
    main()
