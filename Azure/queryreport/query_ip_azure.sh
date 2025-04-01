#!/bin/bash
# query_ip_azure.sh - Query Azure network traffic logs by IP address
# Usage: ./query_ip_azure.sh <IP address> [days]

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check parameters
if [ -z "$1" ]; then
    echo -e "${RED}Error: Please provide an IP address${NC}"
    echo "Usage: ./query_ip_azure.sh <IP address> [days]"
    exit 1
fi

TARGET_IP=$1
DAYS_BACK=${2:-30} # Default: query the last 30 days

# Calculate time range
START_DATE=$(date -d "$DAYS_BACK days ago" +%Y-%m-%dT%H:%M:%SZ)
END_DATE=$(date +%Y-%m-%dT%H:%M:%SZ)
DATE_TAG=$(date +%Y%m%d%H%M%S)
OUTPUT_DIR="ip_traffic_${TARGET_IP//\./_}_${DATE_TAG}"

echo -e "${BLUE}=====================================${NC}"
echo -e "${GREEN}IP Traffic Log Query Tool${NC}"
echo -e "${BLUE}=====================================${NC}"
echo -e "Target IP: ${YELLOW}$TARGET_IP${NC}"
echo -e "Time Range: ${YELLOW}$START_DATE${NC} to ${YELLOW}$END_DATE${NC}"
echo -e "Output Directory: ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "${BLUE}=====================================${NC}"

# Create output directory
mkdir -p $OUTPUT_DIR
echo "Created output directory: $OUTPUT_DIR"

# Login check
echo -e "\n${BLUE}[1/7] Checking Azure login status...${NC}"
SUBSCRIPTION_CHECK=$(az account show 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "You are not logged in to Azure. Starting login process..."
    az login
    if [ $? -ne 0 ]; then
        echo -e "${RED}Login failed. Please check your credentials and try again${NC}"
        exit 1
    fi
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)
echo -e "Current Subscription: ${YELLOW}$SUBSCRIPTION_ID${NC}"
echo -e "Current Tenant: ${YELLOW}$TENANT_ID${NC}"

# Save all subscription information
echo -e "\n${BLUE}[2/7] Getting all available subscriptions...${NC}"
az account list --query "[].{name:name, id:id, isDefault:isDefault}" -o json > "$OUTPUT_DIR/subscriptions.json"
echo "Found $(jq '. | length' "$OUTPUT_DIR/subscriptions.json") subscriptions"

# Find Log Analytics workspaces
echo -e "\n${BLUE}[3/7] Finding all Log Analytics workspaces...${NC}"

# Initialize workspace list file
echo "[]" > "$OUTPUT_DIR/workspaces.json"

# Iterate through all subscriptions to find workspaces
for SUB_ID in $(jq -r '.[].id' "$OUTPUT_DIR/subscriptions.json"); do
    SUB_NAME=$(jq -r '.[] | select(.id=="'$SUB_ID'") | .name' "$OUTPUT_DIR/subscriptions.json")
    echo -e "Checking subscription: ${YELLOW}$SUB_NAME${NC}"
    
    # Switch subscription
    az account set --subscription $SUB_ID
    
    # Get workspaces in current subscription
    WORKSPACES=$(az monitor log-analytics workspace list --query "[].{name:name, resourceGroup:resourceGroup, id:id, location:location, customerId:customerId}" -o json)
    
    # Merge to main workspace list
    WORKSPACE_COUNT=$(echo $WORKSPACES | jq '. | length')
    if [ "$WORKSPACE_COUNT" -gt "0" ]; then
        # Add subscription info to each workspace
        WORKSPACES_WITH_SUB=$(echo $WORKSPACES | jq --arg subid "$SUB_ID" --arg subname "$SUB_NAME" '[.[] | . + {subscriptionId: $subid, subscriptionName: $subname}]')
        
        # Merge to main list
        jq -s '.[0] + .[1]' "$OUTPUT_DIR/workspaces.json" <(echo $WORKSPACES_WITH_SUB) > "$OUTPUT_DIR/temp.json"
        mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/workspaces.json"
        
        echo "Found $WORKSPACE_COUNT workspaces in subscription $SUB_NAME"
    else
        echo "No workspaces found in subscription $SUB_NAME"
    fi
done

TOTAL_WORKSPACES=$(jq '. | length' "$OUTPUT_DIR/workspaces.json")
echo -e "Found ${GREEN}$TOTAL_WORKSPACES${NC} Log Analytics workspaces"

# Check Network Watcher status
echo -e "\n${BLUE}[4/7] Checking Network Watcher status...${NC}"

# Initialize Network Watcher list
echo "[]" > "$OUTPUT_DIR/network_watchers.json"

# Iterate through all subscriptions to check Network Watcher
for SUB_ID in $(jq -r '.[].id' "$OUTPUT_DIR/subscriptions.json"); do
    SUB_NAME=$(jq -r '.[] | select(.id=="'$SUB_ID'") | .name' "$OUTPUT_DIR/subscriptions.json")
    echo -e "Checking subscription: ${YELLOW}$SUB_NAME${NC}"
    
    # Switch subscription
    az account set --subscription $SUB_ID
    
    # Get Network Watcher in current subscription
    WATCHERS=$(az network watcher list --query "[].{name:name, resourceGroup:resourceGroup, id:id, location:location}" -o json)
    
    # Merge to main list
    WATCHER_COUNT=$(echo $WATCHERS | jq '. | length')
    if [ "$WATCHER_COUNT" -gt "0" ]; then
        # Add subscription info to each Network Watcher
        WATCHERS_WITH_SUB=$(echo $WATCHERS | jq --arg subid "$SUB_ID" --arg subname "$SUB_NAME" '[.[] | . + {subscriptionId: $subid, subscriptionName: $subname}]')
        
        # Merge to main list
        jq -s '.[0] + .[1]' "$OUTPUT_DIR/network_watchers.json" <(echo $WATCHERS_WITH_SUB) > "$OUTPUT_DIR/temp.json"
        mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/network_watchers.json"
        
        echo "Found $WATCHER_COUNT Network Watchers in subscription $SUB_NAME"
    else
        echo "No Network Watchers found in subscription $SUB_NAME"
    fi
done

TOTAL_WATCHERS=$(jq '. | length' "$OUTPUT_DIR/network_watchers.json")
echo -e "Found ${GREEN}$TOTAL_WATCHERS${NC} Network Watchers"

# Find NSG flow log configurations
echo -e "\n${BLUE}[5/7] Finding NSG flow log configurations...${NC}"

# Initialize flow log list
echo "[]" > "$OUTPUT_DIR/flow_logs.json"

# Iterate through all Network Watcher to check flow logs
for WATCHER_INDEX in $(seq 0 $(($(jq '. | length' "$OUTPUT_DIR/network_watchers.json")-1))); do
    WATCHER=$(jq -r ".[$WATCHER_INDEX]" "$OUTPUT_DIR/network_watchers.json")
    WATCHER_NAME=$(echo $WATCHER | jq -r '.name')
    WATCHER_LOCATION=$(echo $WATCHER | jq -r '.location')
    WATCHER_SUB_ID=$(echo $WATCHER | jq -r '.subscriptionId')
    WATCHER_SUB_NAME=$(echo $WATCHER | jq -r '.subscriptionName')
    
    echo -e "Checking Network Watcher: ${YELLOW}$WATCHER_NAME${NC} (location: $WATCHER_LOCATION, subscription: $WATCHER_SUB_NAME)"
    
    # Switch subscription
    az account set --subscription $WATCHER_SUB_ID
    
    # Get NSGs in current region
    NSGS=$(az network nsg list --query "[?location=='$WATCHER_LOCATION'].{name:name, resourceGroup:resourceGroup, id:id}" -o json)
    NSG_COUNT=$(echo $NSGS | jq '. | length')
    
    if [ "$NSG_COUNT" -gt "0" ]; then
        echo "Found $NSG_COUNT NSGs in region $WATCHER_LOCATION"
        
        # Iterate through NSGs to check flow logs
        for NSG_INDEX in $(seq 0 $(($(echo $NSGS | jq '. | length')-1))); do
            NSG=$(echo $NSGS | jq -r ".[$NSG_INDEX]")
            NSG_NAME=$(echo $NSG | jq -r '.name')
            NSG_RG=$(echo $NSG | jq -r '.resourceGroup')
            
            echo -e "  Checking NSG: ${YELLOW}$NSG_NAME${NC} (resource group: $NSG_RG)"
            
            # Get flow log configuration for NSG
            FLOW_LOG=$(az network watcher flow-log show --location $WATCHER_LOCATION --nsg $NSG_NAME --resource-group $NSG_RG 2>/dev/null)
            
            if [ $? -eq 0 ]; then
                # Check if flow log is enabled
                ENABLED=$(echo $FLOW_LOG | jq -r '.enabled')
                
                if [ "$ENABLED" == "true" ]; then
                    echo -e "  ${GREEN}Found enabled flow log configuration${NC}"
                    
                    # Add NSG and subscription info
                    FLOW_LOG_WITH_INFO=$(echo $FLOW_LOG | jq --arg nsgname "$NSG_NAME" --arg nsgrg "$NSG_RG" --arg subid "$WATCHER_SUB_ID" --arg subname "$WATCHER_SUB_NAME" '. + {nsgName: $nsgname, nsgResourceGroup: $nsgrg, subscriptionId: $subid, subscriptionName: $subname}')
                    
                    # Merge to main list
                    jq -s '.[0] + [$1]' "$OUTPUT_DIR/flow_logs.json" <(echo $FLOW_LOG_WITH_INFO) > "$OUTPUT_DIR/temp.json"
                    mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/flow_logs.json"
                else
                    echo -e "  ${YELLOW}Found disabled flow log configuration${NC}"
                fi
            else
                echo -e "  ${YELLOW}No flow log configuration found${NC}"
            fi
        done
    else
        echo "No NSGs found in region $WATCHER_LOCATION"
    fi
done

TOTAL_FLOW_LOGS=$(jq '. | length' "$OUTPUT_DIR/flow_logs.json")
echo -e "Found ${GREEN}$TOTAL_FLOW_LOGS${NC} enabled flow log configurations"

# Query Log Analytics workspaces using KQL
echo -e "\n${BLUE}[6/7] Querying Log Analytics workspaces using KQL...${NC}"

# Initialize result counter
TOTAL_RESULTS=0

# Iterate through all workspaces to execute query
for WORKSPACE_INDEX in $(seq 0 $(($(jq '. | length' "$OUTPUT_DIR/workspaces.json")-1))); do
    WORKSPACE=$(jq -r ".[$WORKSPACE_INDEX]" "$OUTPUT_DIR/workspaces.json")
    WORKSPACE_NAME=$(echo $WORKSPACE | jq -r '.name')
    WORKSPACE_RG=$(echo $WORKSPACE | jq -r '.resourceGroup')
    WORKSPACE_SUB_ID=$(echo $WORKSPACE | jq -r '.subscriptionId')
    WORKSPACE_SUB_NAME=$(echo $WORKSPACE | jq -r '.subscriptionName')
    WORKSPACE_ID=$(echo $WORKSPACE | jq -r '.customerId')
    
    echo -e "Querying workspace: ${YELLOW}$WORKSPACE_NAME${NC} (subscription: $WORKSPACE_SUB_NAME)"
    
    # Switch subscription
    az account set --subscription $WORKSPACE_SUB_ID
    
    # Build KQL query - Network Traffic Analytics
    KQL_QUERY_NETWORK="
    AzureNetworkAnalytics_CL
    | where TimeGenerated between (datetime('$START_DATE') .. datetime('$END_DATE'))
    | where SrcIP_s == '$TARGET_IP' or DestIP_s == '$TARGET_IP'
    | project 
        TimeGenerated, 
        NSGName_s, 
        NSGRules_s, 
        SrcIP_s, 
        SrcPort_d, 
        DestIP_s, 
        DestPort_d, 
        L4Protocol_s, 
        FlowDirection_s, 
        FlowStatus_s, 
        BytesSent_d, 
        BytesReceived_d,
        VM_s,
        Subnet_s,
        InboundFlows_d,
        OutboundFlows_d,
        AllowedInFlows_d,
        AllowedOutFlows_d,
        DeniedInFlows_d,
        DeniedOutFlows_d
    | sort by TimeGenerated desc
    | limit 10000
    "
    
    # Execute network traffic query
    echo "Executing network traffic query..."
    NETWORK_RESULTS=$(az monitor log-analytics query --workspace $WORKSPACE_NAME --resource-group $WORKSPACE_RG --analytics-query "$KQL_QUERY_NETWORK" -o json 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        NETWORK_COUNT=$(echo $NETWORK_RESULTS | jq '. | length')
        
        if [ "$NETWORK_COUNT" -gt "0" ]; then
            echo -e "${GREEN}Found $NETWORK_COUNT network traffic records${NC}"
            
            # Add workspace info to results
            NETWORK_RESULTS_WITH_INFO=$(echo $NETWORK_RESULTS | jq --arg wsname "$WORKSPACE_NAME" --arg wsrg "$WORKSPACE_RG" --arg subid "$WORKSPACE_SUB_ID" --arg subname "$WORKSPACE_SUB_NAME" '[.[] | . + {workspaceName: $wsname, workspaceResourceGroup: $wsrg, subscriptionId: $subid, subscriptionName: $subname}]')
            
            # Save results
            echo $NETWORK_RESULTS_WITH_INFO > "$OUTPUT_DIR/network_traffic_${WORKSPACE_NAME}.json"
            
            # Update total result counter
            TOTAL_RESULTS=$((TOTAL_RESULTS + NETWORK_COUNT))
            
            # Generate CSV
            echo "TimeGenerated,NSGName,SrcIP,SrcPort,DestIP,DestPort,Protocol,Direction,Status,BytesSent,BytesReceived,VM,Subnet,WorkspaceName,SubscriptionName" > "$OUTPUT_DIR/network_traffic_${WORKSPACE_NAME}.csv"
            
            echo $NETWORK_RESULTS_WITH_INFO | jq -r '.[] | [
                .TimeGenerated, 
                .NSGName_s, 
                .SrcIP_s, 
                .SrcPort_d, 
                .DestIP_s, 
                .DestPort_d, 
                .L4Protocol_s, 
                .FlowDirection_s, 
                .FlowStatus_s, 
                .BytesSent_d, 
                .BytesReceived_d,
                .VM_s,
                .Subnet_s,
                .workspaceName,
                .subscriptionName
            ] | @csv' >> "$OUTPUT_DIR/network_traffic_${WORKSPACE_NAME}.csv"
            
            # Execute statistical analysis
            echo "Executing statistical analysis..."
            
            # Protocol and port statistics
            KQL_QUERY_STATS="
            AzureNetworkAnalytics_CL
            | where TimeGenerated between (datetime('$START_DATE') .. datetime('$END_DATE'))
            | where SrcIP_s == '$TARGET_IP' or DestIP_s == '$TARGET_IP'
            | summarize 
                FlowCount=count(), 
                TotalBytes=sum(BytesSent_d + BytesReceived_d),
                AllowedFlows=countif(FlowStatus_s == 'A'),
                DeniedFlows=countif(FlowStatus_s == 'D')
                by L4Protocol_s, DestPort_d
            | sort by TotalBytes desc
            | limit 50
            "
            
            STATS_RESULTS=$(az monitor log-analytics query --workspace $WORKSPACE_NAME --resource-group $WORKSPACE_RG --analytics-query "$KQL_QUERY_STATS" -o json 2>/dev/null)
            
            if [ $? -eq 0 ] && [ "$(echo $STATS_RESULTS | jq '. | length')" -gt "0" ]; then
                echo "Saving statistical analysis results..."
                echo $STATS_RESULTS > "$OUTPUT_DIR/traffic_stats_${WORKSPACE_NAME}.json"
                
                # Generate CSV
                echo "Protocol,Port,FlowCount,TotalBytes,AllowedFlows,DeniedFlows" > "$OUTPUT_DIR/traffic_stats_${WORKSPACE_NAME}.csv"
                
                echo $STATS_RESULTS | jq -r '.[] | [
                    .L4Protocol_s, 
                    .DestPort_d, 
                    .FlowCount, 
                    .TotalBytes, 
                    .AllowedFlows,
                    .DeniedFlows
                ] | @csv' >> "$OUTPUT_DIR/traffic_stats_${WORKSPACE_NAME}.csv"
            fi
            
            # Source and destination IP statistics
            KQL_QUERY_IP_STATS="
            AzureNetworkAnalytics_CL
            | where TimeGenerated between (datetime('$START_DATE') .. datetime('$END_DATE'))
            | where SrcIP_s == '$TARGET_IP' or DestIP_s == '$TARGET_IP'
            | extend PeerIP = iff(SrcIP_s == '$TARGET_IP', DestIP_s, SrcIP_s)
            | extend Direction = iff(SrcIP_s == '$TARGET_IP', 'Outbound', 'Inbound')
            | summarize 
                FlowCount=count(), 
                TotalBytes=sum(BytesSent_d + BytesReceived_d),
                AllowedFlows=countif(FlowStatus_s == 'A'),
                DeniedFlows=countif(FlowStatus_s == 'D')
                by PeerIP, Direction
            | sort by TotalBytes desc
            | limit 100
            "
            
            IP_STATS_RESULTS=$(az monitor log-analytics query --workspace $WORKSPACE_NAME --resource-group $WORKSPACE_RG --analytics-query "$KQL_QUERY_IP_STATS" -o json 2>/dev/null)
            
            if [ $? -eq 0 ] && [ "$(echo $IP_STATS_RESULTS | jq '. | length')" -gt "0" ]; then
                echo "Saving IP statistics analysis results..."
                echo $IP_STATS_RESULTS > "$OUTPUT_DIR/ip_stats_${WORKSPACE_NAME}.json"
                
                # Generate CSV
                echo "PeerIP,Direction,FlowCount,TotalBytes,AllowedFlows,DeniedFlows" > "$OUTPUT_DIR/ip_stats_${WORKSPACE_NAME}.csv"
                
                echo $IP_STATS_RESULTS | jq -r '.[] | [
                    .PeerIP, 
                    .Direction, 
                    .FlowCount, 
                    .TotalBytes, 
                    .AllowedFlows,
                    .DeniedFlows
                ] | @csv' >> "$OUTPUT_DIR/ip_stats_${WORKSPACE_NAME}.csv"
            fi
            
            # Time series analysis
            KQL_QUERY_TIMESERIES="
            AzureNetworkAnalytics_CL
            | where TimeGenerated between (datetime('$START_DATE') .. datetime('$END_DATE'))
            | where SrcIP_s == '$TARGET_IP' or DestIP_s == '$TARGET_IP'
            | summarize 
                FlowCount=count(), 
                TotalBytes=sum(BytesSent_d + BytesReceived_d),
                AllowedFlows=countif(FlowStatus_s == 'A'),
                DeniedFlows=countif(FlowStatus_s == 'D')
                by bin(TimeGenerated, 1h)
            | sort by TimeGenerated asc
            "
            
            TIMESERIES_RESULTS=$(az monitor log-analytics query --workspace $WORKSPACE_NAME --resource-group $WORKSPACE_RG --analytics-query "$KQL_QUERY_TIMESERIES" -o json 2>/dev/null)
            
            if [ $? -eq 0 ] && [ "$(echo $TIMESERIES_RESULTS | jq '. | length')" -gt "0" ]; then
                echo "Saving time series analysis results..."
                echo $TIMESERIES_RESULTS > "$OUTPUT_DIR/timeseries_${WORKSPACE_NAME}.json"
                
                # Generate CSV
                echo "TimeGenerated,FlowCount,TotalBytes,AllowedFlows,DeniedFlows" > "$OUTPUT_DIR/timeseries_${WORKSPACE_NAME}.csv"
                
                echo $TIMESERIES_RESULTS | jq -r '.[] | [
                    .TimeGenerated, 
                    .FlowCount, 
                    .TotalBytes, 
                    .AllowedFlows,
                    .DeniedFlows
                ] | @csv' >> "$OUTPUT_DIR/timeseries_${WORKSPACE_NAME}.csv"
            fi
            
        else
            echo -e "${YELLOW}No network traffic records found${NC}"
        fi
    else
        echo -e "${YELLOW}Query failed or workspace does not have AzureNetworkAnalytics_CL table${NC}"
    fi
    
    # Query security event table
    echo "Querying security event table..."
    KQL_QUERY_SECURITY="
    SecurityEvent
    | where TimeGenerated between (datetime('$START_DATE') .. datetime('$END_DATE'))
    | where SourceIp == '$TARGET_IP' or DestinationIp == '$TARGET_IP'
    | project 
        TimeGenerated, 
        EventID, 
        Activity, 
        Computer, 
        Account, 
        SourceIp, 
        DestinationIp, 
        DestinationPort
    | sort by TimeGenerated desc
    | limit 1000
    "
    
    SECURITY_RESULTS=$(az monitor log-analytics query --workspace $WORKSPACE_NAME --resource-group $WORKSPACE_RG --analytics-query "$KQL_QUERY_SECURITY" -o json 2>/dev/null)
    
    if [ $? -eq 0 ] && [ "$(echo $SECURITY_RESULTS | jq '. | length')" -gt "0" ]; then
        SECURITY_COUNT=$(echo $SECURITY_RESULTS | jq '. | length')
        echo -e "${GREEN}Found $SECURITY_COUNT security event records${NC}"
        
        # Add workspace info
        SECURITY_RESULTS_WITH_INFO=$(echo $SECURITY_RESULTS | jq --arg wsname "$WORKSPACE_NAME" --arg wsrg "$WORKSPACE_RG" --arg subid "$WORKSPACE_SUB_ID" --arg subname "$WORKSPACE_SUB_NAME" '[.[] | . + {workspaceName: $wsname, workspaceResourceGroup: $wsrg, subscriptionId: $subid, subscriptionName: $subname}]')
        
        # Save results
        echo $SECURITY_RESULTS_WITH_INFO > "$OUTPUT_DIR/security_events_${WORKSPACE_NAME}.json"
        
        # Update total result counter
        TOTAL_RESULTS=$((TOTAL_RESULTS + SECURITY_COUNT))
        
        # Generate CSV
        echo "TimeGenerated,EventID,Activity,Computer,Account,SourceIp,DestinationIp,DestinationPort,WorkspaceName,SubscriptionName" > "$OUTPUT_DIR/security_events_${WORKSPACE_NAME}.csv"
        
        echo $SECURITY_RESULTS_WITH_INFO | jq -r '.[] | [
            .TimeGenerated, 
            .EventID, 
            .Activity, 
            .Computer, 
            .Account, 
            .SourceIp, 
            .DestinationIp, 
            .DestinationPort,
            .workspaceName,
            .subscriptionName
        ] | @csv' >> "$OUTPUT_DIR/security_events_${WORKSPACE_NAME}.csv"
    fi
done

echo -e "Found ${GREEN}$TOTAL_RESULTS${NC} records related to IP $TARGET_IP in all workspaces"

# Query Azure resources using Azure Resource Graph
echo -e "\n${BLUE}[7/7] Querying Azure resources using Azure Resource Graph...${NC}"

# Build query
echo "Building Azure Resource Graph query..."
ARG_QUERY="Resources 
| where type =~ 'microsoft.network/networkinterfaces' 
| where properties.ipConfigurations[0].properties.privateIPAddress =~ '$TARGET_IP' 
  or properties.ipConfigurations[0].properties.publicIPAddress.id != '' 
| extend publicIpId = tostring(properties.ipConfigurations[0].properties.publicIPAddress.id) 
| join kind=leftouter (
    Resources 
    | where type =~ 'microsoft.network/publicipaddresses' 
    | extend ipAddress = tostring(properties.ipAddress) 
    | project id, ipAddress
) on \$left.publicIpId == \$right.id 
| where ipAddress =~ '$TARGET_IP' or properties.ipConfigurations[0].properties.privateIPAddress =~ '$TARGET_IP' 
| extend vmId = tostring(properties.virtualMachine.id) 
| project id, name, resourceGroup, subscriptionId, location, privateIp=properties.ipConfigurations[0].properties.privateIPAddress, publicIp=ipAddress, vmId"

echo "Executing Azure Resource Graph query..."
ARG_RESULTS=$(az graph query -q "$ARG_QUERY" --query "data" -o json)

if [ $? -eq 0 ]; then
    ARG_COUNT=$(echo $ARG_RESULTS | jq '. | length')
    
    if [ "$ARG_COUNT" -gt "0" ]; then
        echo -e "${GREEN}Found $ARG_COUNT Azure resources related to IP $TARGET_IP${NC}"
        
        # Save results
        echo $ARG_RESULTS > "$OUTPUT_DIR/related_resources.json"
        
        # Generate CSV
        echo "id,name,resourceGroup,subscriptionId,location,privateIp,publicIp,vmId" > "$OUTPUT_DIR/related_resources.csv"
        
        echo $ARG_RESULTS | jq -r '.[] | [
            .id,
            .name,
            .resourceGroup,
            .subscriptionId,
            .location,
            .privateIp,
            .publicIp,
            .vmId
        ] | @csv' >> "$OUTPUT_DIR/related_resources.csv"
        
        # Query related VM information
        echo -e "\nQuerying related VM information..."
        VM_IDS=$(echo $ARG_RESULTS | jq -r '.[].vmId' | grep -v "null" | sort | uniq)
        
        if [ -n "$VM_IDS" ]; then
            # Build VM query
            VM_ID_LIST=$(echo $VM_IDS | tr '\n' ' ' | sed 's/ /", "/g')
            VM_ID_LIST="\"$VM_ID_LIST\""
            VM_QUERY="Resources 
            | where type =~ 'microsoft.compute/virtualmachines' 
            | where id in~ ($VM_ID_LIST) 
            | extend osType = properties.storageProfile.osDisk.osType 
            | extend osName = properties.extended.instanceView.osName 
            | extend osVersion = properties.extended.instanceView.osVersion 
            | extend computerName = properties.osProfile.computerName 
            | project id, name, resourceGroup, subscriptionId, location, osType, osName, osVersion, computerName, tags"
            
            echo "Executing VM information query..."
            VM_RESULTS=$(az graph query -q "$VM_QUERY" --query "data" -o json)
            
            if [ $? -eq 0 ] && [ "$(echo $VM_RESULTS | jq '. | length')" -gt "0" ]; then
                echo -e "${GREEN}Found $(echo $VM_RESULTS | jq '. | length') related VMs${NC}"
                echo $VM_RESULTS > "$OUTPUT_DIR/related_vms.json"
            else
                echo -e "${YELLOW}No related VM information found${NC}"
            fi
        else
            echo -e "${YELLOW}No related VM IDs found${NC}"
        fi
    else
        echo -e "${YELLOW}No Azure resources related to IP $TARGET_IP found${NC}"
        
        # Try to find communicating resources
        echo "Trying to find communicating resources..."
        COMM_QUERY="Resources 
        | where type =~ 'microsoft.network/networksecuritygroups' 
        | where properties.securityRules[*].properties.sourceAddressPrefix contains '$TARGET_IP' 
           or properties.securityRules[*].properties.destinationAddressPrefix contains '$TARGET_IP' 
        | project id, name, resourceGroup, subscriptionId, location, rules=properties.securityRules"
        
        COMM_RESULTS=$(az graph query -q "$COMM_QUERY" --query "data" -o json)
        
        if [ $? -eq 0 ] && [ "$(echo $COMM_RESULTS | jq '. | length')" -gt "0" ]; then
            echo -e "${GREEN}Found $(echo $COMM_RESULTS | jq '. | length') NSG rules related to IP $TARGET_IP${NC}"
            echo $COMM_RESULTS > "$OUTPUT_DIR/related_nsg_rules.json"
        else
            echo -e "${YELLOW}No NSG rules related to IP $TARGET_IP found${NC}"
        fi
    fi
else
    echo -e "${YELLOW}Azure Resource Graph query failed${NC}"
fi

# Create summary report
echo -e "\n${BLUE}Creating summary report...${NC}"

# Merge all network traffic results
echo "Merging all network traffic results..."
echo "[]" > "$OUTPUT_DIR/all_network_traffic.json"

for NETWORK_FILE in $OUTPUT_DIR/network_traffic_*.json; do
    if [ -f "$NETWORK_FILE" ]; then
        jq -s '.[0] + .[1]' "$OUTPUT_DIR/all_network_traffic.json" "$NETWORK_FILE" > "$OUTPUT_DIR/temp.json"
        mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/all_network_traffic.json"
    fi
done

# Create summary CSV
echo "Creating summary CSV..."
echo "TimeGenerated,NSGName,SrcIP,SrcPort,DestIP,DestPort,Protocol,Direction,Status,BytesSent,BytesReceived,VM,Subnet,WorkspaceName,SubscriptionName" > "$OUTPUT_DIR/all_network_traffic.csv"

cat $OUTPUT_DIR/network_traffic_*.csv | grep -v "TimeGenerated" >> "$OUTPUT_DIR/all_network_traffic.csv"

# Create HTML report
echo "Creating HTML report..."
cat > "$OUTPUT_DIR/report.html"