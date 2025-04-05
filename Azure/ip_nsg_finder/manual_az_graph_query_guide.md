# Azure NSG 流日志手动查询指南

本指南提供了使用 Azure CLI 和 Resource Graph 命令手动执行 IP NSG Finder 脚本所有步骤的详细说明，可用于故障排除和验证结果。

## 前提条件

1. 安装并配置 Azure CLI：
   ```powershell
   # 检查 Azure CLI 安装
   az --version

   # 登录 Azure
   az login
   ```

2. 确保已安装 Azure CLI Resource Graph 扩展：
   ```powershell
   # 安装 Resource Graph 扩展（如果未安装）
   az extension add --name resource-graph
   ```

## 步骤 1：查找与 IP 关联的网络接口

### 1.1 查询公共 IP 地址

```powershell
# 替换 TARGET_IP 为目标 IP 地址
$targetIp = "TARGET_IP"
az graph query -q "Resources | where type =~ 'Microsoft.Network/publicIPAddresses' | where properties.ipAddress =~ '$targetIp' | project id, name, resourceGroup, subscriptionId, ipAddress=properties.ipAddress, nicId=properties.ipConfiguration.id" --query "data" -o json
```

### 1.2 查询网络接口

如果上一步找到了相关的网络接口信息，使用该信息进一步查询：

```powershell
# 替换 NIC_ID 为上一步结果中的 nicId 值（提取相关部分）
$nicId = "NIC_ID"
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkInterfaces' | where id =~ '$nicId' | project id, name, resourceGroup, subscriptionId, privateIp=properties.ipConfigurations[0].properties.privateIPAddress, nsgId=properties.networkSecurityGroup.id" --query "data" -o json
```

### 1.3 直接根据私有 IP 查询网络接口

如果目标 IP 是私有 IP，可以直接查询：

```powershell
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkInterfaces' | mv-expand ipconfig=properties.ipConfigurations | where ipconfig.properties.privateIPAddress =~ '$targetIp' | project id, name, resourceGroup, subscriptionId, privateIp=ipconfig.properties.privateIPAddress, nsgId=properties.networkSecurityGroup.id" --query "data" -o json
```

## 步骤 2：获取 NSG 信息

从上一步获取的 `nsgId` 提取完整的 NSG 信息：

```powershell
# 替换 NSG_ID 为上一步结果中的 nsgId 值
$nsgId = "NSG_ID"
az graph query -q "Resources | where id =~ '$nsgId' | project id, name, resourceGroup, subscriptionId, location" --query "data" -o json
```

## 步骤 3：获取 NSG 流日志配置

```powershell
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkWatchers/flowLogs' | where properties.targetResourceId =~ '$nsgId' | project id, name, resourceGroup, flowLogResourceId=id, workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled=properties.enabled, retentionDays=properties.retentionPolicy.days" --query "data" -o json
```

## 步骤 4：提取 Log Analytics 工作区信息

从上一步的结果中，提取 `workspaceId` 值。验证工作区 ID 是有效的：

```powershell
# 替换 WORKSPACE_ID 为上一步结果中的 workspaceId 值
$workspaceId = "WORKSPACE_ID"

# 如果 workspaceId 是完整的资源 ID
az graph query -q "Resources | where id =~ '$workspaceId' | project id, name, resourceGroup, subscriptionId, location, customerId=properties.customerId" --query "data" -o json

# 如果 workspaceId 只是 GUID（customerId）
az graph query -q "Resources | where type =~ 'Microsoft.OperationalInsights/workspaces' | where properties.customerId =~ '$workspaceId' | project id, name, resourceGroup, subscriptionId, location, customerId=properties.customerId" --query "data" -o json
```

## 步骤 5：创建 KQL 查询

根据目标 IP 和时间范围创建 KQL 查询文件：

```powershell
# 设置时间范围（小时）
$timeRangeHours = 24

# 计算开始和结束时间
$endTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$startTime = (Get-Date).AddHours(-$timeRangeHours).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# 创建查询并保存到文件
$queryContent = @"
AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime('$startTime') .. datetime('$endTime'))
| where FlowStatus_s == "A"
| where SrcIP_s == "$targetIp" or DestIP_s == "$targetIp"
| where NSGList_s contains "$($nsgId.Split('/')[-1])"
| project TimeGenerated, FlowDirection_s, SrcIP_s, DestIP_s, PublicIPs_s, DestPort_d, FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s
| order by TimeGenerated desc
"@

$queryFile = ".\nsg_query.kql"
$queryContent | Out-File -FilePath $queryFile -Encoding utf8
```

## 步骤 6：执行 KQL 查询

使用 Azure CLI 在 Log Analytics 工作区执行查询：

```powershell
# 提取工作区 ID（如果是完整资源 ID，提取最后一部分）
$workspaceIdShort = $workspaceId
if ($workspaceId -like "*/workspaces/*") {
    $workspaceIdShort = $workspaceId.Split('/')[-1]
}

# 执行查询
az monitor log-analytics query --workspace "$workspaceIdShort" --analytics-query "@$queryFile" -o json > query_results.json
```

## 步骤 7：查看和分析结果

```powershell
# 查看结果
cat query_results.json | ConvertFrom-Json | Format-Table
```

## 故障排除

### 检查 NSG 流日志状态

如果没有流日志数据，检查流日志是否已正确配置和启用：

```powershell
# 查看特定 NSG 的所有流日志配置
az network watcher flow-log list --resource-group <资源组名称> --location <区域> --query "[?contains(targetResourceId, '$nsgId')]" -o json
```

### 检查 Log Analytics 查询权限

确认您对工作区有足够的权限：

```powershell
# 获取您的用户主体 ID
$currentUser = az ad signed-in-user show --query "id" -o tsv

# 检查工作区权限
az role assignment list --assignee $currentUser --scope $workspaceId -o json
```

### 直接在 Portal 中测试 KQL 查询

您也可以在 Azure Portal 的 Log Analytics 工作区中测试查询：

1. 登录 Azure Portal
2. 导航到相应的 Log Analytics 工作区
3. 选择"日志"
4. 粘贴步骤 5 中创建的 KQL 查询
5. 点击"运行"按钮

## 注意事项

- 某些命令可能需要根据您的环境进行调整
- 确保您有足够的权限查询所有相关资源
- 流日志数据可能有延迟，最近几小时的数据可能尚未可用
- 大型查询可能需要更长的执行时间
