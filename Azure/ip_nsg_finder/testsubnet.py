# azure_vnet_subnet_query.py
import os
import json
from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest

def query_all_subnets(vnet_name=None, subscription_id=None, resource_group=None):
    """
    Query all subnets using Azure Resource Graph SDK
    Optional parameters allow filtering by specific virtual network, subscription, or resource group
    """
    # Build base query
    query = "Resources | where type =~ 'Microsoft.Network/virtualNetworks'"
    
    # Add optional filters
    if subscription_id:
        query += f" | where subscriptionId =~ '{subscription_id}'"
    if resource_group:
        query += f" | where resourceGroup =~ '{resource_group}'"
    if vnet_name:
        query += f" | where name =~ '{vnet_name}'"
    
    # Complete the query
    query += """
    | mv-expand subnet=properties.subnets
    | project vnetName=name, 
              subnetName=subnet.name, 
              subnetPrefix=subnet.properties.addressPrefix, 
              nsgId=subnet.properties.networkSecurityGroup.id,
              subscriptionId,
              resourceGroup
    """
    
    print(f"Executing query: {query}")
    
    # Create authentication and client
    credential = DefaultAzureCredential()
    client = ResourceGraphClient(credential)
    
    # Use paging to get all results
    all_results = []
    skip = 0
    batch_size = 100  # Number of records per batch
    
    while True:
        print(f"Getting batch: skip={skip}, top={batch_size}")
        
        # Create query request with paging parameters
        request = QueryRequest(
            query=query,
            options={
                "$skip": skip,
                "$top": batch_size
            }
        )
        
        # Execute query
        results = client.resources(request)
        
        # Exit loop if no data returned
        if not results.data:
            break
            
        # Add current batch results
        all_results.extend(results.data)
        print(f"Retrieved {len(results.data)} records, current total: {len(all_results)}")
        
        # If returned record count is less than requested, we've reached the end
        if len(results.data) < batch_size:
            break
            
        # Prepare for next batch
        skip += batch_size
    
    print(f"Query completed, total records retrieved: {len(all_results)}")
    return all_results

def save_results_to_file(results, filename="vnet_subnets.json"):
    """Save results to file"""
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {filename}")

def main():
    # These parameters can be customized as needed
    vnet_name = "your-vnet-name"  # Set to your virtual network name, or None to query all VNets
    subscription_id = None  # Set to your subscription ID, or None to query all subscriptions
    resource_group = None  # Set to your resource group name, or None to query all resource groups
    
    # Execute query
    results = query_all_subnets(vnet_name, subscription_id, resource_group)
    
    # Save results
    save_results_to_file(results)
    
    # Print some statistics
    if results:
        subnet_count = len(results)
        vnet_count = len(set(item["vnetName"] for item in results))
        print(f"Statistics: {vnet_count} virtual networks, {subnet_count} subnets")

if __name__ == "__main__":
    main()