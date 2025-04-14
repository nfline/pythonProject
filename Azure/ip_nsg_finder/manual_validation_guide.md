# Azure NSG流日志查询手动验证指南

本文档提供了一步一步的指南，帮助您手动验证从IP地址到执行KQL查询获取流量数据的完整流程。每个步骤都包含详细解释和可执行的Azure CLI命令。

## 前提条件

1. 已安装Azure CLI
2. 已登录Azure账户
3. 有权限访问相关资源（网络接口、NSG、流日志、Log Analytics）

## 验证步骤

### 步骤1：获取当前Azure账户信息

首先，确认您当前登录的Azure账户，并检查可用的订阅：

```bash
# 查看当前登录账户
az account show

# 列出所有可用订阅
az account list -o table
```

如果需要切换订阅：

```bash
# 切换到特定订阅
az account set --subscription SUBSCRIPTION_ID
```

### 步骤2：通过IP地址查找网络接口和NSG

将以下命令中的`YOUR_TARGET_IP`替换为您要查询的IP地址：

```bash
# 查询与特定IP相关的网络接口
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkInterfaces' | mv-expand ipconfig=properties.ipConfigurations | where ipconfig.properties.privateIPAddress =~ 'YOUR_TARGET_IP' | project id, name, resourceGroup, subscriptionId, privateIp=ipconfig.properties.privateIPAddress, nsgId=properties.networkSecurityGroup.id" --query "data" -o json
```

**期望结果**：一个包含网络接口详细信息的JSON数组，重点关注以下字段：
- `subscriptionId`：Azure订阅ID
- `nsgId`：网络安全组ID（可能为null，如果网络接口没有直接关联NSG）

记录下这些值，将在后续步骤中使用。

### 步骤3：如果步骤2中没有找到NSG，检查子网关联的NSG

如果步骤2中的`nsgId`为null，您需要检查网络接口所在子网是否关联了NSG：

```bash
# 查询网络接口所在的子网
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkInterfaces' | mv-expand ipconfig=properties.ipConfigurations | where ipconfig.properties.privateIPAddress =~ 'YOUR_TARGET_IP' | project subnetId=tostring(ipconfig.properties.subnet.id)" --query "data[].subnetId" -o json
```

获取子网ID后，查询子网关联的NSG：

```bash
# 替换SUBNET_ID为上一步获取的子网ID
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks/subnets' | where id =~ 'SUBNET_ID' | project id, vnetName=split(id, '/')[8], name, nsgId=tostring(properties.networkSecurityGroup.id)" --query "data" -o json
```

记录下获取的`nsgId`，用于后续步骤。

### 步骤4：验证NSG详细信息

使用以下命令验证NSG的详细信息：

```bash
# 替换NSG_ID为之前步骤获取的nsgId
az graph query -q "Resources | where id =~ 'NSG_ID' | project id, name, resourceGroup, subscriptionId, location" --query "data" -o json
```

这一步可以确认NSG是否存在以及基本信息。

### 步骤5：获取NSG流日志配置

```bash
# 替换NSG_ID为之前获取的nsgId
# 可选：添加--subscription SUBSCRIPTION_ID参数
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkWatchers/flowLogs' | where properties.targetResourceId =~ 'NSG_ID' | project id, name, resourceGroup, flowLogResourceId=id, workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled=properties.enabled, retentionDays=properties.retentionPolicy.days" --query "data" -o json
```

**关键输出**：
- `workspaceId`：Log Analytics工作区ID
- `enabled`：流日志是否启用

这是最关键的一步，`workspaceId`是执行KQL查询所必需的。如果没有找到结果或`enabled`为false，可能需要配置NSG流日志。

### 步骤6：准备KQL查询

创建一个包含KQL查询的文件：

```bash
echo 'AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where FlowStatus_s == "A" 
| where SrcIP_s == "YOUR_TARGET_IP" or DestIP_s == "YOUR_TARGET_IP"
| project TimeGenerated, FlowDirection_s, SrcIP_s, DestIP_s, PublicIPs_s, DestPort_d, 
         FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s
| order by TimeGenerated desc' > query.kql
```

将`YOUR_TARGET_IP`替换为您要查询的IP地址。

### 步骤7：执行KQL查询

```bash
# 替换以下参数
# WORKSPACE_ID：步骤5获取的workspaceId
# SUBSCRIPTION_ID：包含工作区的订阅ID
az monitor log-analytics query --workspace "WORKSPACE_ID" --subscription SUBSCRIPTION_ID --analytics-query "@query.kql" -o json
```

如果查询成功，您将看到一个包含流量记录的JSON数组。

## 常见问题及解决方法

### 找不到与IP相关的网络接口

可能原因：
- IP地址不正确
- 网络接口不在当前订阅中
- 您没有权限查看该网络接口

解决方法：
- 确认IP地址正确，并尝试在多个订阅中搜索
- 确认您有权限访问相关资源

### 未找到NSG的流日志配置

可能原因：
- NSG未配置流日志
- 流日志未启用Traffic Analytics
- 流日志配置在不同的订阅中

解决方法：
- 检查NSG是否已配置流日志：
  ```bash
  az network watcher flow-log list --query "[?contains(targetResourceId, 'NSG_ID')]" -o json
  ```
- 如需配置流日志，可参考Azure文档配置NSG流日志和Traffic Analytics

### KQL查询未返回结果

可能原因：
- 时间范围内没有匹配的流量
- 工作区ID不正确
- 流日志未正确发送到工作区

解决方法：
- 尝试扩大时间范围，例如将`ago(24h)`改为`ago(7d)`
- 确认工作区ID正确
- 检查流日志和Traffic Analytics配置

## 总结

通过这些步骤，您可以手动验证从IP地址到获取NSG流日志数据的完整流程。每个步骤都获取必要的信息，最终使用这些信息执行KQL查询获取流量数据。

如有任何问题，请参考完整的Azure文档或联系Azure支持。

## 优化验证流程

以下是一个更简洁、准确且有逻辑的验证流程，特别适用于已知的subscription ID和VNET信息的情况：

### 步骤1：确认IP地址和基本信息

```bash
# 查询与特定IP相关的网络接口，获取基本信息
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkInterfaces' | mv-expand ipconfig=properties.ipConfigurations | where ipconfig.properties.privateIPAddress =~ 'YOUR_TARGET_IP' | project nicName=name, subscriptionId, resourceGroup, vnetName=split(tostring(ipconfig.properties.subnet.id), '/')[8], subnetName=split(tostring(ipconfig.properties.subnet.id), '/')[10], privateIp=ipconfig.properties.privateIPAddress, directNsgId=properties.networkSecurityGroup.id" --query "data" -o json
```

这一步会返回：
- subscriptionId
- resourceGroup
- vnetName（从子网ID提取）
- subnetName（从子网ID提取）
- directNsgId（网络接口直接关联的NSG，可能为null）

### 步骤2：直接查询子网关联的NSG

使用步骤1获取的信息，直接查询子网关联的NSG：

```bash
# 使用已知的资源组、VNET和子网名称直接查询
az network vnet subnet show --resource-group "RESOURCE_GROUP" --vnet-name "VNET_NAME" --name "SUBNET_NAME" --subscription "SUBSCRIPTION_ID" --query "networkSecurityGroup.id" -o json
```

这一步会返回子网关联的NSG ID。

### 步骤3：获取NSG流日志配置和工作区ID

使用获取到的NSG ID，直接查询其流日志配置：

```bash
# 查询NSG流日志配置
az network watcher flow-log list --subscription "SUBSCRIPTION_ID" --query "[?contains(targetResourceId, 'NSG_ID')].{workspaceId:flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled:enabled}" -o json
```

这一步会返回：
- workspaceId（Log Analytics工作区ID）
- enabled（流日志是否启用）

### 步骤4：执行KQL查询

创建KQL查询文件：

```bash
echo 'AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where FlowStatus_s == "A" 
| where SrcIP_s == "YOUR_TARGET_IP" or DestIP_s == "YOUR_TARGET_IP"
| project TimeGenerated, FlowDirection_s, SrcIP_s, DestIP_s, PublicIPs_s, DestPort_d, 
         FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s
| order by TimeGenerated desc' > query.kql
```

执行查询：

```bash
# 执行KQL查询
az monitor log-analytics query --workspace "WORKSPACE_ID" --subscription "SUBSCRIPTION_ID" --analytics-query "@query.kql" -o json
```

### 一键验证脚本

以下PowerShell脚本可以自动完成整个验证过程：

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

# 使用直接关联的NSG或子网NSG
$nsgId = if ($nicInfo.directNsgId) { $nicInfo.directNsgId } else { $subnetNsgId }
$nsgName = $nsgId.Split('/')[-1]

Write-Host "使用NSG: $nsgName" -ForegroundColor Green

# 步骤3：获取流日志配置
$flowLogs = (az network watcher flow-log list --subscription $nicInfo.subscriptionId --query "[?contains(targetResourceId, '$nsgId')].{workspaceId:flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled:enabled}" -o json) | ConvertFrom-Json

if ($flowLogs -and $flowLogs.Length -gt 0 -and $flowLogs[0].enabled) {
    Write-Host "找到启用的流日志配置" -ForegroundColor Green
    Write-Host "工作区ID: $($flowLogs[0].workspaceId)" -ForegroundColor Green
    
    # 步骤4：创建并执行KQL查询
    "AzureNetworkAnalytics_CL
    | where TimeGenerated > ago(24h)
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

这个优化的验证流程利用了已知的subscription ID和VNET信息，减少了查询步骤，提高了准确性和效率。
