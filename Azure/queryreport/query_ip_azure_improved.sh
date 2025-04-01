#!/bin/bash
# query_ip_azure_improved.sh - Query Azure network traffic logs by IP address
# Usage: ./query_ip_azure_improved.sh <IP address> [days]
# This improved version first finds the NSG associated with the IP, then queries only relevant logs

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check parameters
if [ -z "$1" ]; then
    echo -e "${RED}Error: Please provide an IP address${NC}"
    echo "Usage: ./query_ip_azure_improved.sh <IP address> [days]"
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
echo -e "${GREEN}IP Traffic Log Query Tool (Improved)${NC}"
echo -e "${BLUE}=====================================${NC}"
echo -e "Target IP: ${YELLOW}$TARGET_IP${NC}"
echo -e "Time Range: ${YELLOW}$START_DATE${NC} to ${YELLOW}$END_DATE${NC}"
echo -e "Output Directory: ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "${BLUE}=====================================${NC}"

# Create output directory
mkdir -p $OUTPUT_DIR
echo "Created output directory: $OUTPUT_DIR"

# Login check
echo -e "\n${BLUE}[1/5] Checking Azure login status...${NC}"
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

# Step 2: Find resources associated with the IP using Resource Graph
echo -e "\n${BLUE}[2/5] Finding resources associated with IP ${TARGET_IP}...${NC}"

# Query for network interfaces with this IP
echo "Searching for network interfaces with IP $TARGET_IP..."
IP_RESOURCES=$(az graph query -q "Resources | where type =~ 'microsoft.network/networkinterfaces' | where properties.ipConfigurations[0].properties.privateIPAddress =~ '$TARGET_IP' | project id, name, resourceGroup, subscriptionId, location, nsgId = tostring(properties.networkSecurityGroup.id)" --query "data" -o json)

# Get NSG IDs directly associated with these interfaces
NSG_IDS=$(echo $IP_RESOURCES | jq -r '.[].nsgId' | grep -v "null")

# Save resources associated with IP
echo $IP_RESOURCES > "$OUTPUT_DIR/associated_resources.json"
RESOURCE_COUNT=$(echo $IP_RESOURCES | jq '. | length')

if [ "$RESOURCE_COUNT" -gt "0" ]; then
    echo -e "${GREEN}Found $RESOURCE_COUNT resources with IP $TARGET_IP${NC}"
    
    # Generate CSV
    echo "id,name,resourceGroup,subscriptionId,location,nsgId" > "$OUTPUT_DIR/associated_resources.csv"
    echo $IP_RESOURCES | jq -r '.[] | [.id, .name, .resourceGroup, .subscriptionId, .location, .nsgId] | @csv' >> "$OUTPUT_DIR/associated_resources.csv"
else
    echo -e "${YELLOW}No resources directly associated with IP $TARGET_IP found${NC}"
fi

# Step 3: Find NSGs that reference this IP in their rules
echo -e "\n${BLUE}[3/5] Finding NSGs that reference IP ${TARGET_IP} in their rules...${NC}"

NSG_RULES_QUERY="Resources 
| where type =~ 'microsoft.network/networksecuritygroups' 
| where properties.securityRules[*].properties.sourceAddressPrefix contains '$TARGET_IP' 
   or properties.securityRules[*].properties.destinationAddressPrefix contains '$TARGET_IP' 
| project id, name, resourceGroup, subscriptionId, location, rules=properties.securityRules"

NSG_RULES=$(az graph query -q "$NSG_RULES_QUERY" --query "data" -o json)
echo $NSG_RULES > "$OUTPUT_DIR/related_nsg_rules.json"

NSG_RULES_COUNT=$(echo $NSG_RULES | jq '. | length')
if [ "$NSG_RULES_COUNT" -gt "0" ]; then
    echo -e "${GREEN}Found $NSG_RULES_COUNT NSGs with rules referencing IP $TARGET_IP${NC}"
    
    # Extract NSG IDs from rules
    NSG_RULE_IDS=$(echo $NSG_RULES | jq -r '.[].id')
    
    # Combine with direct NSG IDs
    if [ -n "$NSG_RULE_IDS" ]; then
        if [ -n "$NSG_IDS" ]; then
            NSG_IDS=$(echo -e "$NSG_IDS\n$NSG_RULE_IDS" | sort | uniq)
        else
            NSG_IDS=$NSG_RULE_IDS
        fi
    fi
else
    echo -e "${YELLOW}No NSGs found with rules referencing IP $TARGET_IP${NC}"
fi

# Step 4: Find flow logs for identified NSGs
echo -e "\n${BLUE}[4/5] Finding flow logs for identified NSGs...${NC}"

# Initialize workspace tracking files
echo "[]" > "$OUTPUT_DIR/target_workspaces.json"
echo "[]" > "$OUTPUT_DIR/flow_logs.json"

if [ -z "$NSG_IDS" ]; then
    echo -e "${YELLOW}No NSGs found associated with IP $TARGET_IP${NC}"
    echo -e "${YELLOW}Switching to querying all workspaces in current subscription${NC}"
    
    # Get workspaces in current subscription
    WORKSPACES=$(az monitor log-analytics workspace list --query "[].{name:name, resourceGroup:resourceGroup, id:id, location:location, customerId:customerId, subscriptionId:'$SUBSCRIPTION_ID'}" -o json)
    echo $WORKSPACES > "$OUTPUT_DIR/workspaces.json"
else
    TOTAL_NSGS=0
    NSG_COUNT=$(echo "$NSG_IDS" | wc -l)
    echo -e "${GREEN}Found $NSG_COUNT NSGs to check for flow logs${NC}"
    
    # For each NSG, find its flow log configuration 
    for NSG_ID in $NSG_IDS; do
        TOTAL_NSGS=$((TOTAL_NSGS + 1))
        echo -e "[$TOTAL_NSGS/$NSG_COUNT] Checking NSG: ${YELLOW}$NSG_ID${NC}"
        
        # Extract NSG name, resource group, and subscription
        NSG_SUB=$(echo $NSG_ID | cut -d'/' -f3)
        NSG_RG=$(echo $NSG_ID | cut -d'/' -f5)
        NSG_NAME=$(echo $NSG_ID | cut -d'/' -f9)
        
        # Switch to NSG subscription
        echo "Switching to subscription: $NSG_SUB"
        az account set --subscription $NSG_SUB 2>/dev/null
        
        # Get NSG details
        NSG_LOCATION=$(az network nsg show --ids $NSG_ID --query "location" -o tsv 2>/dev/null)
        
        if [ -z "$NSG_LOCATION" ]; then
            echo -e "${YELLOW}Cannot access NSG details. Skipping...${NC}"
            continue
        fi
        
        # Get flow log for this NSG
        echo "Checking flow log for NSG $NSG_NAME in location $NSG_LOCATION..."
        FLOW_LOG=$(az network watcher flow-log show --location $NSG_LOCATION --nsg $NSG_NAME --resource-group $NSG_RG 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            ENABLED=$(echo $FLOW_LOG | jq -r '.enabled')
            
            if [ "$ENABLED" == "true" ]; then
                echo -e "  ${GREEN}Found enabled flow log configuration${NC}"
                
                # Add NSG info to flow log
                FLOW_LOG_WITH_INFO=$(echo $FLOW_LOG | jq --arg nsgid "$NSG_ID" --arg nsgname "$NSG_NAME" --arg nsgrg "$NSG_RG" --arg subid "$NSG_SUB" '. + {nsgId: $nsgid, nsgName: $nsgname, nsgResourceGroup: $nsgrg, subscriptionId: $subid}')
                
                # Store flow log info
                jq -s '.[0] + [$1]' "$OUTPUT_DIR/flow_logs.json" <(echo $FLOW_LOG_WITH_INFO) > "$OUTPUT_DIR/temp.json"
                mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/flow_logs.json"
                
                # Extract workspace ID if Traffic Analytics is enabled
                TRAFFIC_ANALYTICS_ENABLED=$(echo $FLOW_LOG | jq -r '.flowAnalyticsConfiguration.enabled')
                
                if [ "$TRAFFIC_ANALYTICS_ENABLED" == "true" ]; then
                    WORKSPACE_ID=$(echo $FLOW_LOG | jq -r '.flowAnalyticsConfiguration.workspaceId')
                    WORKSPACE_RG=$(echo $FLOW_LOG | jq -r '.flowAnalyticsConfiguration.workspaceRegion')
                    
                    if [ -n "$WORKSPACE_ID" ] && [ "$WORKSPACE_ID" != "null" ]; then
                        echo -e "  ${GREEN}Found workspace ID: $WORKSPACE_ID${NC}"
                        
                        # Find workspace details using Resource Graph
                        WORKSPACE_QUERY="Resources 
                        | where type =~ 'microsoft.operationalinsights/workspaces' 
                        | where properties.customerId =~ '$WORKSPACE_ID' 
                        | project name, resourceGroup, subscriptionId, location, customerId=properties.customerId"
                        
                        WORKSPACE_INFO=$(az graph query -q "$WORKSPACE_QUERY" --query "data" -o json)
                        
                        if [ "$(echo $WORKSPACE_INFO | jq '. | length')" -gt "0" ]; then
                            WORKSPACE_NAME=$(echo $WORKSPACE_INFO | jq -r '.[0].name')
                            WORKSPACE_RG=$(echo $WORKSPACE_INFO | jq -r '.[0].resourceGroup')
                            WORKSPACE_SUB=$(echo $WORKSPACE_INFO | jq -r '.[0].subscriptionId')
                            WORKSPACE_LOCATION=$(echo $WORKSPACE_INFO | jq -r '.[0].location')
                            
                            echo -e "  ${GREEN}Found workspace: $WORKSPACE_NAME (RG: $WORKSPACE_RG, Sub: $WORKSPACE_SUB)${NC}"
                            
                            # Add to target workspaces
                            WORKSPACE_DATA="{\"name\":\"$WORKSPACE_NAME\",\"resourceGroup\":\"$WORKSPACE_RG\",\"subscriptionId\":\"$WORKSPACE_SUB\",\"location\":\"$WORKSPACE_LOCATION\",\"customerId\":\"$WORKSPACE_ID\",\"nsgId\":\"$NSG_ID\"}"
                            jq -s '.[0] + [$1]' "$OUTPUT_DIR/target_workspaces.json" <(echo $WORKSPACE_DATA) > "$OUTPUT_DIR/temp.json"
                            mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/target_workspaces.json"
                        fi
                    fi
                fi
            else
                echo -e "  ${YELLOW}Flow log exists but is disabled${NC}"
            fi
        else
            echo -e "  ${YELLOW}No flow log configuration found${NC}"
        fi
    done
    
    # If no workspaces found in NSGs, try getting workspaces in current subscription
    if [ "$(jq '. | length' "$OUTPUT_DIR/target_workspaces.json")" -eq "0" ]; then
        echo -e "${YELLOW}No workspaces found in NSG flow logs. Checking current subscription...${NC}"
        WORKSPACES=$(az monitor log-analytics workspace list --query "[].{name:name, resourceGroup:resourceGroup, id:id, location:location, customerId:customerId, subscriptionId:'$SUBSCRIPTION_ID'}" -o json)
        echo $WORKSPACES > "$OUTPUT_DIR/workspaces.json"
        
        # Move workspaces to target file
        cp "$OUTPUT_DIR/workspaces.json" "$OUTPUT_DIR/target_workspaces.json"
    else
        # Copy target workspaces to workspaces file
        cp "$OUTPUT_DIR/target_workspaces.json" "$OUTPUT_DIR/workspaces.json"
    fi
fi

# Step 5: Query relevant workspaces
echo -e "\n${BLUE}[5/5] Querying workspaces for traffic data...${NC}"

# Initialize result counter
TOTAL_RESULTS=0

# Get list of workspaces to query
WORKSPACE_COUNT=$(jq '. | length' "$OUTPUT_DIR/target_workspaces.json")
echo -e "Found ${GREEN}$WORKSPACE_COUNT${NC} workspaces to query"

# Iterate through workspaces to execute queries
for WORKSPACE_INDEX in $(seq 0 $((WORKSPACE_COUNT-1))); do
    WORKSPACE=$(jq -r ".[$WORKSPACE_INDEX]" "$OUTPUT_DIR/target_workspaces.json")
    WORKSPACE_NAME=$(echo $WORKSPACE | jq -r '.name')
    WORKSPACE_RG=$(echo $WORKSPACE | jq -r '.resourceGroup')
    WORKSPACE_SUB_ID=$(echo $WORKSPACE | jq -r '.subscriptionId')
    WORKSPACE_ID=$(echo $WORKSPACE | jq -r '.customerId')
    
    echo -e "Querying workspace: ${YELLOW}$WORKSPACE_NAME${NC} (Subscription: $WORKSPACE_SUB_ID)"
    
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
            NETWORK_RESULTS_WITH_INFO=$(echo $NETWORK_RESULTS | jq --arg wsname "$WORKSPACE_NAME" --arg wsrg "$WORKSPACE_RG" --arg subid "$WORKSPACE_SUB_ID" '[.[] | . + {workspaceName: $wsname, workspaceResourceGroup: $wsrg, subscriptionId: $subid}]')
            
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
                .subscriptionId
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
        SECURITY_RESULTS_WITH_INFO=$(echo $SECURITY_RESULTS | jq --arg wsname "$WORKSPACE_NAME" --arg wsrg "$WORKSPACE_RG" --arg subid "$WORKSPACE_SUB_ID" '[.[] | . + {workspaceName: $wsname, workspaceResourceGroup: $wsrg, subscriptionId: $subid}]')
        
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
            .subscriptionId
        ] | @csv' >> "$OUTPUT_DIR/security_events_${WORKSPACE_NAME}.csv"
    fi
done

echo -e "Found ${GREEN}$TOTAL_RESULTS${NC} records related to IP $TARGET_IP in all workspaces"

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

for CSV_FILE in $OUTPUT_DIR/network_traffic_*.csv; do
    if [ -f "$CSV_FILE" ]; then
        tail -n +2 "$CSV_FILE" >> "$OUTPUT_DIR/all_network_traffic.csv"
    fi
done

echo -e "${BLUE}=====================================${NC}"
echo -e "${GREEN}Analysis complete!${NC}"
echo -e "Results saved to: ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "${BLUE}=====================================${NC}"
