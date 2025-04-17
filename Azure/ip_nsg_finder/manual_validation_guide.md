# Azure NSG流日志查询手动验证指南

本文档提供了一步一步的指南，帮助您手动验证从IP地址到执行KQL查询获取流量数据的完整流程。每个步骤都包含详细命令和参数传递说明。

## 前提条件

- 已安装 Azure CLI 并已登录
- 对于使用 Log Analytics 查询的步骤，需要安装 `az cli-ml` 扩展
- 目标IP地址所在的虚拟机和网络资源的访问权限

## 手动验证流程

整个流程可以分为几个关键步骤，每一步都会产生下一步所需的参数：

### 步骤1：根据IP地址查找网络接口和基本信息

执行以下命令查找与IP地址关联的网络接口及其基本信息：

```bash
# 将YOUR_TARGET_IP替换为您要查询的IP地址
TARGET_IP="YOUR_TARGET_IP"

# 查询与IP相关的网络接口
az graph query -q "Resources 
| where type =~ 'microsoft.network/networkinterfaces' 
| where properties.ipConfigurations contains '$TARGET_IP' 
| project id, name, resourceGroup, subscriptionId, subnetId = tostring(properties.ipConfigurations[0].properties.subnet.id), nsgId = tostring(properties.networkSecurityGroup.id)" 
--query "data" -o json
```

**预期输出包含以下参数（需记录用于下一步）：**
- nicName：网络接口名称
- subscriptionId：订阅ID
- resourceGroup：资源组名称
- vnetName：虚拟网络名称
- subnetName：子网名称
- directNsgId：直接关联到网络接口的NSG ID（如果有）

### 步骤2：查找子网关联的NSG

使用步骤1获取的信息，查询子网关联的NSG：

```bash
# 使用上一步获取的参数
SUBSCRIPTION_ID="步骤1获取的subscriptionId"
RESOURCE_GROUP="步骤1获取的resourceGroup"
VNET_NAME="步骤1获取的vnetName"
SUBNET_NAME="步骤1获取的subnetName"

# 查询子网关联的NSG
az network vnet subnet show --resource-group "$RESOURCE_GROUP" --vnet-name "$VNET_NAME" --name "$SUBNET_NAME" --subscription "$SUBSCRIPTION_ID" --query "networkSecurityGroup.id" -o json
```

**预期输出：**
- 子网关联的NSG ID（如果存在）

### 步骤3：确定要使用的NSG ID

根据步骤1和步骤2的结果，确定要使用的NSG ID：

```bash
# 使用步骤1和步骤2的结果
DIRECT_NSG_ID="步骤1获取的directNsgId（如果有）"
SUBNET_NSG_ID="步骤2获取的NSG ID（如果有）"

# 选择要使用的NSG ID（优先使用直接关联的NSG）
NSG_ID=${DIRECT_NSG_ID:-$SUBNET_NSG_ID}
echo "使用的NSG ID: $NSG_ID"

# 从NSG ID提取NSG名称
NSG_NAME=$(echo $NSG_ID | awk -F'/' '{print $NF}')
echo "NSG名称: $NSG_NAME"
```

**预期输出：**
- 最终使用的NSG ID和NSG名称

### 步骤4：查询NSG流日志配置

使用步骤3确定的NSG ID，查询其流日志配置：

```bash
# 使用步骤3获取的参数
SUBSCRIPTION_ID="步骤1获取的subscriptionId"
NSG_ID="步骤3确定的NSG ID"

# 查询NSG流日志配置
az graph query -q "Resources 
| where type =~ 'Microsoft.Network/networkWatchers/flowLogs' 
| where properties.targetResourceId =~ '$NSG_ID' 
| project id, name, resourceGroup, flowLogResourceId=id, workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled=properties.enabled, retentionDays=properties.retentionPolicy.days" 
--subscription "$SUBSCRIPTION_ID" --query "data" -o json
```

**预期输出：**
- 流日志是否启用（enabled属性）
- Log Analytics工作区ID（workspaceId属性）

### 步骤5：执行KQL查询获取流日志数据

使用步骤4获取的工作区ID，执行KQL查询：

```bash
# 使用步骤4获取的参数
WORKSPACE_ID="步骤4获取的workspaceId"
SUBSCRIPTION_ID="步骤1获取的subscriptionId"
TARGET_IP="您要查询的IP地址"

# 创建KQL查询文件
cat > query.kql << EOF
AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime('$(date -u -d "-24 hours" "+%Y-%m-%dT%H:%M:%SZ")') .. datetime('$(date -u "+%Y-%m-%dT%H:%M:%SZ")'))
| where FlowStatus_s == "A"
| where SrcIP_s == "$TARGET_IP" or DestIP_s == "$TARGET_IP"
| project TimeGenerated, FlowDirection_s, SrcIP_s, DestIP_s, PublicIPs_s, DestPort_d, 
         FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s
| order by TimeGenerated desc
EOF

# 执行KQL查询
az monitor log-analytics query --workspace "$WORKSPACE_ID" --subscription "$SUBSCRIPTION_ID" --analytics-query "@query.kql" -o json > "flow_logs_$TARGET_IP.json"
```

**预期输出：**
- 符合条件的流日志数据，保存在JSON文件中

## 完整的PowerShell脚本示例

以下是一个集成上述所有步骤的PowerShell脚本示例：

```powershell
# 设置参数
$targetIp = "YOUR_TARGET_IP"

# 步骤1：获取基本信息
$nicInfo = (az graph query -q "Resources | where type =~ 'Microsoft.Network/networkInterfaces' | mv-expand ipconfig=properties.ipConfigurations | where ipconfig.properties.privateIPAddress =~ '$targetIp' | project nicName=name, subscriptionId, resourceGroup, vnetName=split(tostring(ipconfig.properties.subnet.id), '/')[8], subnetName=split(tostring(ipconfig.properties.subnet.id), '/')[10], privateIp=ipconfig.properties.privateIPAddress, directNsgId=properties.networkSecurityGroup.id" --query "data[0]" -o json) | ConvertFrom-Json

Write-Host "找到网络接口: $($nicInfo.nicName)" -ForegroundColor Green
Write-Host "订阅ID: $($nicInfo.subscriptionId)" -ForegroundColor Green
Write-Host "资源组: $($nicInfo.resourceGroup)" -ForegroundColor Green
Write-Host "虚拟网络: $($nicInfo.vnetName)" -ForegroundColor Green
Write-Host "子网: $($nicInfo.subnetName)" -ForegroundColor Green

# 步骤2：查询子网NSG
$subnetNsgId = (az network vnet subnet show --resource-group $nicInfo.resourceGroup --vnet-name $nicInfo.vnetName --name $nicInfo.subnetName --subscription $nicInfo.subscriptionId --query "networkSecurityGroup.id" -o json) | ConvertFrom-Json

Write-Host "子网关联的NSG: $subnetNsgId" -ForegroundColor Green

# 步骤3：确定使用的NSG
$nsgId = if ($nicInfo.directNsgId) { $nicInfo.directNsgId } else { $subnetNsgId }
$nsgName = $nsgId.Split('/')[-1]

Write-Host "使用NSG: $nsgName" -ForegroundColor Green

# 步骤4：获取流日志配置
$flowLogs = (az network watcher flow-log list --subscription $nicInfo.subscriptionId --query "[?contains(targetResourceId, '$nsgId')].{workspaceId:flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled:enabled}" -o json) | ConvertFrom-Json

if ($flowLogs -and $flowLogs.Length -gt 0 -and $flowLogs[0].enabled) {
    Write-Host "找到启用的流日志配置" -ForegroundColor Green
    Write-Host "工作区ID: $($flowLogs[0].workspaceId)" -ForegroundColor Green
    
    # 步骤5：创建并执行KQL查询
    $startTime = (Get-Date).AddHours(-24).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $endTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    "AzureNetworkAnalytics_CL
    | where TimeGenerated between (datetime('$startTime') .. datetime('$endTime'))
    | where FlowStatus_s == `"A`" 
    | where SrcIP_s == `"$targetIp`" or DestIP_s == `"$targetIp`"
    | project TimeGenerated, FlowDirection_s, SrcIP_s, DestIP_s, PublicIPs_s, DestPort_d, 
             FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s
    | order by TimeGenerated desc" | Out-File -FilePath "query.kql"
    
    Write-Host "执行KQL查询..." -ForegroundColor Yellow
    $queryResults = (az monitor log-analytics query --workspace $flowLogs[0].workspaceId --subscription $nicInfo.subscriptionId --analytics-query "@query.kql" -o json) | ConvertFrom-Json
    
    Write-Host "查询完成，找到 $($queryResults.Length) 条记录" -ForegroundColor Green
    
    # 保存结果
    $queryResults | ConvertTo-Json -Depth 10 > "flow_logs_$targetIp.json"
    Write-Host "结果已保存到 flow_logs_$targetIp.json" -ForegroundColor Green
} else {
    Write-Host "未找到启用的流日志配置" -ForegroundColor Red
}
```

## 常见问题及解决方案

### 1. 找不到网络接口或子网

如果步骤1无法找到网络接口，可能是以下原因：
- IP地址输入错误
- IP地址不属于Azure虚拟网络
- 权限不足

解决方法：
- 验证IP地址正确性
- 检查权限是否足够
- 尝试在特定订阅中查询：`--subscription "SUBSCRIPTION_ID"`

### 2. 找不到NSG流日志配置

可能原因：
- NSG未配置流日志
- 流日志配置在不同的订阅中

解决方法：
- 检查NSG是否已配置流日志：
  ```bash
  az network watcher flow-log show --nsg $NSG_ID --subscription $SUBSCRIPTION_ID
  ```
- 检查不同订阅中的流日志配置

### 3. 查询工作区时出错

可能原因：
- 工作区ID不正确
- 没有工作区的访问权限
- 工作区中没有流日志数据

解决方法：
- 验证工作区ID是否正确
- 确认有权访问工作区
- 检查流日志配置是否正确启用并发送到指定工作区

## Azure Resource Graph 查询限制及替代方案

通过实际测试，我们发现 Azure Resource Graph 查询（`az graph query`）存在**128条记录的硬性限制**。这意味着对于拥有大量子网（超过128个）的虚拟网络，Resource Graph 查询无法返回完整的子网列表。

以下是验证测试结果：

```bash
# 尝试使用 limit 增加结果数量，但结果仍然限制在 128 条
az graph query -q "Resources 
| where type =~ 'Microsoft.Network/virtualNetworks' 
| where name =~ 'VNET_NAME'
| mv-expand subnet=properties.subnets 
| project vnetName=name, subnetName=subnet.name, subnetPrefix=subnet.properties.addressPrefix
| limit 1000" 
--query "data" -o json

# 结果显示 "count": 128
```

### 替代解决方案

对于需要查询所有子网的情况，应当使用 `az network vnet subnet` 命令直接查询虚拟网络的子网，这种方法没有数量限制：

```bash
# 直接列出虚拟网络中的所有子网
az network vnet subnet list --resource-group "RESOURCE_GROUP" --vnet-name "VNET_NAME" --subscription "SUBSCRIPTION_ID" -o json
```

这个命令会返回完整的子网列表，包括每个子网的详细信息，如地址前缀、NSG 关联等。

## 总结

通过这个手动验证指南，您可以逐步从IP地址开始，找到相关的NSG，并查询其流日志数据。整个过程涉及以下关键参数的传递：

1. IP地址 → 查询网络接口 → 获取基本信息（订阅ID、资源组、虚拟网络、子网和直接NSG）
2. 基本信息 → 查询子网NSG → 获取子网NSG ID
3. 直接NSG ID + 子网NSG ID → 确定使用的NSG ID
4. NSG ID → 查询流日志配置 → 获取工作区ID
5. 工作区ID + IP地址 → 执行KQL查询 → 获取流日志数据

通过这种结构化的步骤和参数传递方法，您可以有效地手动验证自动化脚本的工作流程，或在自动化脚本不可用时执行手动查询。
