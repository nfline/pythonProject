# Azure Resource Graph 子网查询验证指南

本文档专注于验证通过Azure Resource Graph查询子网信息的各种方法，特别是获取子网关联的NSG信息。

## 基础知识

Azure Resource Graph是一种高性能的资源查询服务，但查询语法和过滤条件需要精确匹配。以下是一系列逐步验证命令，帮助确定问题所在。

## 1. 验证Resource Graph基本查询功能

首先，验证Azure Resource Graph是否能正常工作：

```bash
# 简单查询，验证Resource Graph功能
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' | limit 5" -o json
```

如果此命令返回结果，说明Resource Graph基本功能正常。

## 2. 验证子网资源类型查询

接下来，验证子网资源类型的查询是否正确：

```bash
# 验证子网资源类型查询
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks/subnets' | limit 5" -o json
```

**注意**：这个查询可能不会返回结果，因为在Resource Graph中，子网通常不作为独立资源存在，而是作为虚拟网络的嵌套资源。

## 3. 正确查询子网的方法

由于子网是虚拟网络的嵌套资源，正确的查询方法是：

```bash
# 正确查询虚拟网络及其子网
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' | project id, name, subnets=properties.subnets" -o json
```

这将返回虚拟网络及其包含的子网列表。

## 4. 展开子网列表进行查询

要查询特定子网，可以使用`mv-expand`操作符展开子网列表：

```bash
# 展开子网列表
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' | mv-expand subnet=properties.subnets | project vnetName=name, subnetName=subnet.name, subnetId=subnet.id, nsgId=subnet.properties.networkSecurityGroup.id" -o json
```

## 5. 按子网名称筛选

如果您知道子网名称，可以这样筛选：

```bash
# 按子网名称筛选
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' | mv-expand subnet=properties.subnets | where subnet.name =~ 'SUBNET_NAME' | project vnetName=name, subnetName=subnet.name, subnetId=subnet.id, nsgId=subnet.properties.networkSecurityGroup.id" -o json
```

## 6. 按子网ID片段筛选

如果您有子网ID的一部分，可以使用`contains`操作符：

```bash
# 按子网ID片段筛选
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' | mv-expand subnet=properties.subnets | where subnet.id contains 'SUBNET_ID_PART' | project vnetName=name, subnetName=subnet.name, subnetId=subnet.id, nsgId=subnet.properties.networkSecurityGroup.id" -o json
```

## 7. 从IP地址一步查询到子网NSG

这是最直接的方法，从IP地址直接查询到子网及其NSG：

```bash
# 从IP地址查询到子网NSG
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkInterfaces' | mv-expand ipconfig=properties.ipConfigurations | where ipconfig.properties.privateIPAddress =~ 'YOUR_TARGET_IP' | extend subnetId = tostring(ipconfig.properties.subnet.id) | project nicName=name, privateIp=ipconfig.properties.privateIPAddress, subnetId" -o json
```

获取子网ID后，使用以下查询获取NSG：

```bash
# 使用子网ID片段查询虚拟网络和子网
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' | mv-expand subnet=properties.subnets | where subnet.id contains 'SUBNET_ID_PART' | project vnetName=name, subnetName=subnet.name, subnetId=subnet.id, nsgId=subnet.properties.networkSecurityGroup.id" -o json
```

## 8. 组合查询（一步到位）

以下是一个组合查询，尝试在一个命令中完成从IP到子网NSG的查询：

```bash
# 组合查询：从IP到子网NSG
az graph query -q "Resources | where type =~ 'Microsoft.Network/networkInterfaces' | mv-expand ipconfig=properties.ipConfigurations | where ipconfig.properties.privateIPAddress =~ 'YOUR_TARGET_IP' | extend subnetId = tostring(ipconfig.properties.subnet.id) | join kind=leftouter (Resources | where type =~ 'Microsoft.Network/virtualNetworks' | mv-expand subnet=properties.subnets | extend subnetId = subnet.id | project subnetId, vnetName=name, subnetName=subnet.name, nsgId=subnet.properties.networkSecurityGroup.id) on subnetId | project nicName=name, privateIp=ipconfig.properties.privateIPAddress, subnetId, vnetName, subnetName, nsgId" -o json
```

## 9. 使用Resource Graph查询特定资源组中的子网

如果您知道资源组名称，可以缩小查询范围：

```bash
# 查询特定资源组中的子网
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' and resourceGroup =~ 'RESOURCE_GROUP_NAME' | mv-expand subnet=properties.subnets | project vnetName=name, subnetName=subnet.name, subnetId=subnet.id, nsgId=subnet.properties.networkSecurityGroup.id" -o json
```

## 10. 验证子网是否有关联的NSG

有些子网可能没有关联NSG，可以使用以下查询验证：

```bash
# 验证子网是否有关联的NSG
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' | mv-expand subnet=properties.subnets | extend hasNsg = isnotempty(subnet.properties.networkSecurityGroup.id) | project vnetName=name, subnetName=subnet.name, hasNsg, nsgId=subnet.properties.networkSecurityGroup.id" -o json
```

## 11. 查询所有已关联NSG的子网

如果您想查看所有已关联NSG的子网：

```bash
# 查询所有已关联NSG的子网
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' | mv-expand subnet=properties.subnets | where isnotempty(subnet.properties.networkSecurityGroup.id) | project vnetName=name, subnetName=subnet.name, subnetId=subnet.id, nsgId=subnet.properties.networkSecurityGroup.id" -o json
```

## 12. 查询特定NSG关联的所有子网

如果您已知NSG ID，想查询与之关联的所有子网：

```bash
# 查询特定NSG关联的所有子网
az graph query -q "Resources | where type =~ 'Microsoft.Network/virtualNetworks' | mv-expand subnet=properties.subnets | where subnet.properties.networkSecurityGroup.id contains 'NSG_ID_PART' | project vnetName=name, subnetName=subnet.name, subnetId=subnet.id, nsgId=subnet.properties.networkSecurityGroup.id" -o json
```

## 故障排除

如果上述查询都不返回预期结果，可能存在以下问题：

1. **权限问题**：确保您有足够的权限查询虚拟网络资源
2. **资源不存在**：确认子网和NSG确实存在
3. **查询语法错误**：检查查询语法，特别是过滤条件
4. **订阅问题**：确保在正确的订阅上下文中执行查询

## 与az network命令对比验证

为了验证Resource Graph查询结果的准确性，可以与传统的`az network`命令结果进行对比：

```bash
# 使用az network命令查询子网
az network vnet subnet show --resource-group RESOURCE_GROUP_NAME --vnet-name VNET_NAME --name SUBNET_NAME --query "networkSecurityGroup.id" -o json
```

如果`az network`命令返回结果但Resource Graph查询不返回，可能是Resource Graph的数据同步延迟或查询语法问题。

## 总结

Azure Resource Graph查询子网信息时，关键点是：

1. 子网是虚拟网络的嵌套资源，需要使用`mv-expand`展开
2. 使用`contains`而不是完全匹配可以提高查询成功率
3. 组合查询可以一步从IP地址获取到子网NSG信息
4. 如果Resource Graph查询不成功，可以回退到`az network`命令
