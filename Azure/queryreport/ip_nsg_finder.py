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
from typing import List, Dict, Any, Optional

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
    print(f"保存数据到 {file_path}")

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

def ip_in_subnet(ip_int: int, subnet_prefix: str) -> bool:
    """Check if IP is within subnet range"""
    try:
        # Parse subnet prefix (e.g. "10.0.0.0/24")
        subnet_addr, subnet_mask = subnet_prefix.split('/')
        subnet_mask = int(subnet_mask)
        
        # Parse subnet address
        subnet_parts = subnet_addr.split('.')
        if len(subnet_parts) != 4:
            return False
            
        # Convert to integer
        subnet_int = (int(subnet_parts[0]) << 24) + (int(subnet_parts[1]) << 16) + \
                     (int(subnet_parts[2]) << 8) + int(subnet_parts[3])
                     
        # Calculate mask
        mask_int = (0xFFFFFFFF << (32 - subnet_mask)) & 0xFFFFFFFF
        
        # Check if IP is within subnet range
        return (ip_int & mask_int) == (subnet_int & mask_int)
    except (ValueError, IndexError) as e:
        print_warning(f"解析子网前缀时出错: {subnet_prefix}, 错误: {str(e)}")
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
            
            # Convert IP to integer
            ip_parts = target_ip.split('.')
            if len(ip_parts) != 4:
                print_error(f"无效的IP地址格式: {target_ip}")
                return nsg_ids
                
            ip_int = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + \
                     (int(ip_parts[2]) << 8) + int(ip_parts[3])
            
            # Check each subnet to see if it contains this IP
            for subnet in all_subnets:
                subnet_prefix = subnet.get('subnetPrefix')
                
                # Subnet prefix could be string or list
                prefixes = []
                if isinstance(subnet_prefix, list):
                    prefixes.extend(subnet_prefix)
                else:
                    prefixes.append(subnet_prefix)
                
                for prefix in prefixes:
                    if prefix and ip_in_subnet(ip_int, prefix):
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

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Find NSGs associated with an IP address')
    parser.add_argument('ip_address', help='The IP address to query')
    
    args = parser.parse_args()
    
    print_info("=" * 60)
    print_success(f"IP NSG 查找器")
    print_info("=" * 60)
    print(f"目标IP: {args.ip_address}")
    print_info("=" * 60)
    
    # Find NSGs associated with IP
    nsg_ids = find_nsgs_by_ip(args.ip_address)
    
    # Validate NSGs found
    if nsg_ids:
        # Additional processing can be added here, such as querying NSG flow logs
        print_success("\n查找完成！已找到相关NSG。")
    else:
        print_warning("\n查找完成，但未找到相关NSG。")
    
if __name__ == "__main__":
    main()
