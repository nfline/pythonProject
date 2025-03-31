#!/bin/bash
# query-ip-traffic.sh - 通过IP地址查询Azure网络流量日志
# 使用方法: ./query-ip-traffic.sh <IP地址> [天数]

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 检查参数
if [ -z "$1" ]; then
    echo -e "${RED}错误: 请提供IP地址${NC}"
    echo "使用方法: ./query-ip-traffic.sh <IP地址> [天数]"
    exit 1
fi

TARGET_IP=$1
DAYS_BACK=${2:-30} # 默认查询过去30天

# 计算时间范围
START_DATE=$(date -d "$DAYS_BACK days ago" +%Y-%m-%dT%H:%M:%SZ)
END_DATE=$(date +%Y-%m-%dT%H:%M:%SZ)
DATE_TAG=$(date +%Y%m%d%H%M%S)
OUTPUT_DIR="ip_traffic_${TARGET_IP//\./_}_${DATE_TAG}"

echo -e "${BLUE}=====================================${NC}"
echo -e "${GREEN}IP流量日志查询工具${NC}"
echo -e "${BLUE}=====================================${NC}"
echo -e "目标IP: ${YELLOW}$TARGET_IP${NC}"
echo -e "时间范围: ${YELLOW}$START_DATE${NC} 到 ${YELLOW}$END_DATE${NC}"
echo -e "输出目录: ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "${BLUE}=====================================${NC}"

# 创建输出目录
mkdir -p $OUTPUT_DIR
echo "已创建输出目录: $OUTPUT_DIR"

# 登录检查
echo -e "\n${BLUE}[1/7] 检查Azure登录状态...${NC}"
SUBSCRIPTION_CHECK=$(az account show 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "您尚未登录Azure，正在启动登录流程..."
    az login
    if [ $? -ne 0 ]; then
        echo -e "${RED}登录失败，请检查凭据后重试${NC}"
        exit 1
    fi
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)
echo -e "当前订阅: ${YELLOW}$SUBSCRIPTION_ID${NC}"
echo -e "当前租户: ${YELLOW}$TENANT_ID${NC}"

# 保存所有订阅信息
echo -e "\n${BLUE}[2/7] 获取所有可用订阅...${NC}"
az account list --query "[].{name:name, id:id, isDefault:isDefault}" -o json > "$OUTPUT_DIR/subscriptions.json"
echo "找到 $(jq '. | length' "$OUTPUT_DIR/subscriptions.json") 个订阅"

# 查找Log Analytics工作区
echo -e "\n${BLUE}[3/7] 查找所有Log Analytics工作区...${NC}"

# 初始化工作区列表文件
echo "[]" > "$OUTPUT_DIR/workspaces.json"

# 遍历所有订阅查找工作区
for SUB_ID in $(jq -r '.[].id' "$OUTPUT_DIR/subscriptions.json"); do
    SUB_NAME=$(jq -r '.[] | select(.id=="'$SUB_ID'") | .name' "$OUTPUT_DIR/subscriptions.json")
    echo -e "检查订阅: ${YELLOW}$SUB_NAME${NC}"
    
    # 切换订阅
    az account set --subscription $SUB_ID
    
    # 获取当前订阅中的工作区
    WORKSPACES=$(az monitor log-analytics workspace list --query "[].{name:name, resourceGroup:resourceGroup, id:id, location:location, customerId:customerId}" -o json)
    
    # 合并到主工作区列表
    WORKSPACE_COUNT=$(echo $WORKSPACES | jq '. | length')
    if [ "$WORKSPACE_COUNT" -gt "0" ]; then
        # 添加订阅信息到每个工作区
        WORKSPACES_WITH_SUB=$(echo $WORKSPACES | jq --arg subid "$SUB_ID" --arg subname "$SUB_NAME" '[.[] | . + {subscriptionId: $subid, subscriptionName: $subname}]')
        
        # 合并到主列表
        jq -s '.[0] + .[1]' "$OUTPUT_DIR/workspaces.json" <(echo $WORKSPACES_WITH_SUB) > "$OUTPUT_DIR/temp.json"
        mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/workspaces.json"
        
        echo "在订阅 $SUB_NAME 中找到 $WORKSPACE_COUNT 个工作区"
    else
        echo "在订阅 $SUB_NAME 中未找到工作区"
    fi
done

TOTAL_WORKSPACES=$(jq '. | length' "$OUTPUT_DIR/workspaces.json")
echo -e "共找到 ${GREEN}$TOTAL_WORKSPACES${NC} 个Log Analytics工作区"

# 检查Network Watcher状态
echo -e "\n${BLUE}[4/7] 检查Network Watcher状态...${NC}"

# 初始化Network Watcher列表
echo "[]" > "$OUTPUT_DIR/network_watchers.json"

# 遍历所有订阅检查Network Watcher
for SUB_ID in $(jq -r '.[].id' "$OUTPUT_DIR/subscriptions.json"); do
    SUB_NAME=$(jq -r '.[] | select(.id=="'$SUB_ID'") | .name' "$OUTPUT_DIR/subscriptions.json")
    echo -e "检查订阅: ${YELLOW}$SUB_NAME${NC}"
    
    # 切换订阅
    az account set --subscription $SUB_ID
    
    # 获取当前订阅中的Network Watcher
    WATCHERS=$(az network watcher list --query "[].{name:name, resourceGroup:resourceGroup, id:id, location:location}" -o json)
    
    # 合并到主列表
    WATCHER_COUNT=$(echo $WATCHERS | jq '. | length')
    if [ "$WATCHER_COUNT" -gt "0" ]; then
        # 添加订阅信息到每个Network Watcher
        WATCHERS_WITH_SUB=$(echo $WATCHERS | jq --arg subid "$SUB_ID" --arg subname "$SUB_NAME" '[.[] | . + {subscriptionId: $subid, subscriptionName: $subname}]')
        
        # 合并到主列表
        jq -s '.[0] + .[1]' "$OUTPUT_DIR/network_watchers.json" <(echo $WATCHERS_WITH_SUB) > "$OUTPUT_DIR/temp.json"
        mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/network_watchers.json"
        
        echo "在订阅 $SUB_NAME 中找到 $WATCHER_COUNT 个Network Watcher"
    else
        echo "在订阅 $SUB_NAME 中未找到Network Watcher"
    fi
done

TOTAL_WATCHERS=$(jq '. | length' "$OUTPUT_DIR/network_watchers.json")
echo -e "共找到 ${GREEN}$TOTAL_WATCHERS${NC} 个Network Watcher"

# 查找NSG流日志配置
echo -e "\n${BLUE}[5/7] 查找NSG流日志配置...${NC}"

# 初始化流日志列表
echo "[]" > "$OUTPUT_DIR/flow_logs.json"

# 遍历所有Network Watcher检查流日志
for WATCHER_INDEX in $(seq 0 $(($(jq '. | length' "$OUTPUT_DIR/network_watchers.json")-1))); do
    WATCHER=$(jq -r ".[$WATCHER_INDEX]" "$OUTPUT_DIR/network_watchers.json")
    WATCHER_NAME=$(echo $WATCHER | jq -r '.name')
    WATCHER_LOCATION=$(echo $WATCHER | jq -r '.location')
    WATCHER_SUB_ID=$(echo $WATCHER | jq -r '.subscriptionId')
    WATCHER_SUB_NAME=$(echo $WATCHER | jq -r '.subscriptionName')
    
    echo -e "检查Network Watcher: ${YELLOW}$WATCHER_NAME${NC} (位置: $WATCHER_LOCATION, 订阅: $WATCHER_SUB_NAME)"
    
    # 切换订阅
    az account set --subscription $WATCHER_SUB_ID
    
    # 获取当前区域中的所有NSG
    NSGS=$(az network nsg list --query "[?location=='$WATCHER_LOCATION'].{name:name, resourceGroup:resourceGroup, id:id}" -o json)
    NSG_COUNT=$(echo $NSGS | jq '. | length')
    
    if [ "$NSG_COUNT" -gt "0" ]; then
        echo "在位置 $WATCHER_LOCATION 中找到 $NSG_COUNT 个NSG"
        
        # 遍历NSG检查流日志
        for NSG_INDEX in $(seq 0 $(($(echo $NSGS | jq '. | length')-1))); do
            NSG=$(echo $NSGS | jq -r ".[$NSG_INDEX]")
            NSG_NAME=$(echo $NSG | jq -r '.name')
            NSG_RG=$(echo $NSG | jq -r '.resourceGroup')
            
            echo -e "  检查NSG: ${YELLOW}$NSG_NAME${NC} (资源组: $NSG_RG)"
            
            # 获取NSG的流日志配置
            FLOW_LOG=$(az network watcher flow-log show --location $WATCHER_LOCATION --nsg $NSG_NAME --resource-group $NSG_RG 2>/dev/null)
            
            if [ $? -eq 0 ]; then
                # 检查是否启用
                ENABLED=$(echo $FLOW_LOG | jq -r '.enabled')
                
                if [ "$ENABLED" == "true" ]; then
                    echo -e "  ${GREEN}找到已启用的流日志配置${NC}"
                    
                    # 添加NSG和订阅信息
                    FLOW_LOG_WITH_INFO=$(echo $FLOW_LOG | jq --arg nsgname "$NSG_NAME" --arg nsgrg "$NSG_RG" --arg subid "$WATCHER_SUB_ID" --arg subname "$WATCHER_SUB_NAME" '. + {nsgName: $nsgname, nsgResourceGroup: $nsgrg, subscriptionId: $subid, subscriptionName: $subname}')
                    
                    # 合并到主列表
                    jq -s '.[0] + [$1]' "$OUTPUT_DIR/flow_logs.json" <(echo $FLOW_LOG_WITH_INFO) > "$OUTPUT_DIR/temp.json"
                    mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/flow_logs.json"
                else
                    echo -e "  ${YELLOW}找到未启用的流日志配置${NC}"
                fi
            else
                echo -e "  ${YELLOW}未找到流日志配置${NC}"
            fi
        done
    else
        echo "在位置 $WATCHER_LOCATION 中未找到NSG"
    fi
done

TOTAL_FLOW_LOGS=$(jq '. | length' "$OUTPUT_DIR/flow_logs.json")
echo -e "共找到 ${GREEN}$TOTAL_FLOW_LOGS${NC} 个已启用的流日志配置"

# 使用KQL查询Log Analytics工作区
echo -e "\n${BLUE}[6/7] 使用KQL查询Log Analytics工作区...${NC}"

# 初始化结果计数器
TOTAL_RESULTS=0

# 遍历所有工作区执行查询
for WORKSPACE_INDEX in $(seq 0 $(($(jq '. | length' "$OUTPUT_DIR/workspaces.json")-1))); do
    WORKSPACE=$(jq -r ".[$WORKSPACE_INDEX]" "$OUTPUT_DIR/workspaces.json")
    WORKSPACE_NAME=$(echo $WORKSPACE | jq -r '.name')
    WORKSPACE_RG=$(echo $WORKSPACE | jq -r '.resourceGroup')
    WORKSPACE_SUB_ID=$(echo $WORKSPACE | jq -r '.subscriptionId')
    WORKSPACE_SUB_NAME=$(echo $WORKSPACE | jq -r '.subscriptionName')
    WORKSPACE_ID=$(echo $WORKSPACE | jq -r '.customerId')
    
    echo -e "查询工作区: ${YELLOW}$WORKSPACE_NAME${NC} (订阅: $WORKSPACE_SUB_NAME)"
    
    # 切换订阅
    az account set --subscription $WORKSPACE_SUB_ID
    
    # 构建KQL查询 - Network Traffic Analytics
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
    
    # 执行网络流量查询
    echo "执行网络流量查询..."
    NETWORK_RESULTS=$(az monitor log-analytics query --workspace $WORKSPACE_NAME --resource-group $WORKSPACE_RG --analytics-query "$KQL_QUERY_NETWORK" -o json 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        NETWORK_COUNT=$(echo $NETWORK_RESULTS | jq '. | length')
        
        if [ "$NETWORK_COUNT" -gt "0" ]; then
            echo -e "${GREEN}找到 $NETWORK_COUNT 条网络流量记录${NC}"
            
            # 添加工作区信息到结果
            NETWORK_RESULTS_WITH_INFO=$(echo $NETWORK_RESULTS | jq --arg wsname "$WORKSPACE_NAME" --arg wsrg "$WORKSPACE_RG" --arg subid "$WORKSPACE_SUB_ID" --arg subname "$WORKSPACE_SUB_NAME" '[.[] | . + {workspaceName: $wsname, workspaceResourceGroup: $wsrg, subscriptionId: $subid, subscriptionName: $subname}]')
            
            # 保存结果
            echo $NETWORK_RESULTS_WITH_INFO > "$OUTPUT_DIR/network_traffic_${WORKSPACE_NAME}.json"
            
            # 更新总结果计数
            TOTAL_RESULTS=$((TOTAL_RESULTS + NETWORK_COUNT))
            
            # 生成CSV
            echo "正在生成CSV格式..."
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
            
            # 执行统计分析
            echo "执行统计分析..."
            
            # 按协议和端口统计
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
                echo "保存统计分析结果..."
                echo $STATS_RESULTS > "$OUTPUT_DIR/traffic_stats_${WORKSPACE_NAME}.json"
                
                # 生成CSV
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
            
            # 按源目标IP统计
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
                echo "保存IP统计分析结果..."
                echo $IP_STATS_RESULTS > "$OUTPUT_DIR/ip_stats_${WORKSPACE_NAME}.json"
                
                # 生成CSV
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
            
            # 时间序列分析
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
                echo "保存时间序列分析结果..."
                echo $TIMESERIES_RESULTS > "$OUTPUT_DIR/timeseries_${WORKSPACE_NAME}.json"
                
                # 生成CSV
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
            echo -e "${YELLOW}未找到网络流量记录${NC}"
        fi
    else
        echo -e "${YELLOW}查询失败或工作区中没有AzureNetworkAnalytics_CL表${NC}"
    fi
    
    # 查询安全事件表
    echo "查询安全事件表..."
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
        echo -e "${GREEN}找到 $SECURITY_COUNT 条安全事件记录${NC}"
        
        # 添加工作区信息
        SECURITY_RESULTS_WITH_INFO=$(echo $SECURITY_RESULTS | jq --arg wsname "$WORKSPACE_NAME" --arg wsrg "$WORKSPACE_RG" --arg subid "$WORKSPACE_SUB_ID" --arg subname "$WORKSPACE_SUB_NAME" '[.[] | . + {workspaceName: $wsname, workspaceResourceGroup: $wsrg, subscriptionId: $subid, subscriptionName: $subname}]')
        
        # 保存结果
        echo $SECURITY_RESULTS_WITH_INFO > "$OUTPUT_DIR/security_events_${WORKSPACE_NAME}.json"
        
        # 更新总结果计数
        TOTAL_RESULTS=$((TOTAL_RESULTS + SECURITY_COUNT))
        
        # 生成CSV
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

echo -e "在所有工作区中共找到 ${GREEN}$TOTAL_RESULTS${NC} 条与IP $TARGET_IP 相关的记录"

# 使用Microsoft Graph API查询网络流量日志
echo -e "\n${BLUE}[7/7] 使用Microsoft Graph API查询网络流量日志...${NC}"

# 获取访问令牌
echo "获取Microsoft Graph API访问令牌..."
ACCESS_TOKEN=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)

if [ -n "$ACCESS_TOKEN" ]; then
    # 编码日期
    START_DATE_ENCODED=$(echo $START_DATE | sed 's/:/\%3A/g')
    END_DATE_ENCODED=$(echo $END_DATE | sed 's/:/\%3A/g')
    
    # 构建查询URL
    GRAPH_URL="https://graph.microsoft.com/v1.0/security/networkTrafficLogs?\$filter=(sourceAddress eq '$TARGET_IP' or destinationAddress eq '$TARGET_IP') and createdDateTime ge $START_DATE_ENCODED and createdDateTime le $END_DATE_ENCODED&\$top=100"
    
    echo "执行Microsoft Graph API查询..."
    GRAPH_RESULT=$(curl -s -X GET "$GRAPH_URL" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json")
    
    # 检查是否有结果
    GRAPH_VALUE=$(echo $GRAPH_RESULT | jq -r '.value')
    if [ "$GRAPH_VALUE" != "null" ]; then
        GRAPH_COUNT=$(echo $GRAPH_RESULT | jq '.value | length')
        
        if [ "$GRAPH_COUNT" -gt "0" ]; then
            echo -e "${GREEN}通过Graph API找到 $GRAPH_COUNT 条与IP $TARGET_IP 相关的流量记录${NC}"
            
            # 保存结果
            echo $GRAPH_RESULT > "$OUTPUT_DIR/graph_traffic_logs.json"
            
            # 生成CSV
            echo "createdDateTime,sourceAddress,sourcePort,destinationAddress,destinationPort,protocol,trafficDirection,action,bytesTransferred" > "$OUTPUT_DIR/graph_traffic_logs.csv"
            
            echo $GRAPH_RESULT | jq -r '.value[] | [
                .createdDateTime, 
                .sourceAddress, 
                .sourcePort, 
                .destinationAddress, 
                .destinationPort, 
                .protocol, 
                .trafficDirection, 
                .action,
                .bytesTransferred
            ] | @csv' >> "$OUTPUT_DIR/graph_traffic_logs.csv"
            
            # 更新总结果计数
            TOTAL_RESULTS=$((TOTAL_RESULTS + GRAPH_COUNT))
        else
            echo -e "${YELLOW}通过Graph API未找到与IP $TARGET_IP 相关的流量记录${NC}"
        fi
    else
        echo -e "${YELLOW}Graph API查询失败或返回无效响应${NC}"
        echo "API响应:"
        echo $GRAPH_RESULT | jq .
    fi
else
    echo -e "${YELLOW}无法获取Graph API访问令牌，跳过此步骤${NC}"
fi

# 创建汇总报告
echo -e "\n${BLUE}创建汇总报告...${NC}"

# 合并所有网络流量结果
echo "合并所有网络流量结果..."
echo "[]" > "$OUTPUT_DIR/all_network_traffic.json"

for NETWORK_FILE in $OUTPUT_DIR/network_traffic_*.json; do
    if [ -f "$NETWORK_FILE" ]; then
        jq -s '.[0] + .[1]' "$OUTPUT_DIR/all_network_traffic.json" "$NETWORK_FILE" > "$OUTPUT_DIR/temp.json"
        mv "$OUTPUT_DIR/temp.json" "$OUTPUT_DIR/all_network_traffic.json"
    fi
done

# 创建汇总CSV
echo "创建汇总CSV..."
echo "TimeGenerated,NSGName,SrcIP,SrcPort,DestIP,DestPort,Protocol,Direction,Status,BytesSent,BytesReceived,VM,Subnet,WorkspaceName,SubscriptionName" > "$OUTPUT_DIR/all_network_traffic.csv"

cat $OUTPUT_DIR/network_traffic_*.csv | grep -v "TimeGenerated" >> "$OUTPUT_DIR/all_network_traffic.csv"

# 创建HTML报告
echo "创建HTML报告..."
cat > "$OUTPUT_DIR/report.html"