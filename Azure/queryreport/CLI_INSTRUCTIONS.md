# Azure NSG 排查工具命令行指南

## 1. 前置条件验证命令

```bash
# 检查Azure登录状态
az account show --output table

# 安装资源图扩展（首次使用需要）
az extension add --name resource-graph
```

## 2. NSG关联查询命令

```bash
# 通过IP查找关联NSG（Resource Graph查询）
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkSecurityGroups' | where properties.securityRules[].properties.destinationAddressPrefixes contains '<TARGET_IP>' or properties.securityRules[].properties.sourceAddressPrefixes contains '<TARGET_IP>' | project name, resourceGroup" --output table

# 查看NSG详细配置
az network nsg show --name <NSG_NAME> --resource-group <RG_NAME> --query "{Rules:securityRules[*].{Name:name, Priority:priority, Access:access, Direction:direction, Source:sourceAddressPrefix, Dest:destinationAddressPrefix}}" -o json
```

## 3. 流量日志分析命令

```bash
# 查询Log Analytics工作空间（需提前配置流日志）
az monitor log-analytics workspace list --query "[].{Name:name, ID:id}" -o table

# 执行KQL查询示例（时间范围24小时）
az monitor log-analytics query --workspace <WORKSPACE_ID> --analytics-query "AzureNetworkAnalytics_CL | where TimeGenerated >= ago(24h) | where SrcIP_s == '<TARGET_IP>' or DestIP_s == '<TARGET_IP>' | summarize count() by DestPort_d" -o table
```

## 4. 高级Graph查询（IP-NSG关联）

```kusto
Resources
| where type contains "networkSecurityGroups"
| extend nsgRules = properties.securityRules
| mv-expand nsgRule = nsgRules
| where nsgRule.properties.destinationAddressPrefixes has '<TARGET_IP>' 
   or nsgRule.properties.sourceAddressPrefixes has '<TARGET_IP>'
| project subscriptionId, resourceGroup, name, ruleName=nsgRule.name, 
  direction=nsgRule.properties.direction, 
  access=nsgRule.properties.access,
  priority=nsgRule.properties.priority
| order by priority asc
```

## 5. 结果验证命令

```bash
# 检查流日志配置状态
az network watcher flow-log list --location <REGION> --query "[?networkSecurityGroupId=='/subscriptions/<SUB_ID>/resourceGroups/<RG_NAME>/providers/Microsoft.Network/networkSecurityGroups/<NSG_NAME>']"

# 导出NSG规则到文件
az network nsg rule list --nsg-name <NSG_NAME> -g <RG_NAME> -o json > nsg_rules_export.json
```

## 使用提示：
1. 替换<TARGET_IP>为实际IP地址
2. <REGION>使用区域短名（如eastus）
3. 查询结果可重定向到文件：az ... -o json > output.json