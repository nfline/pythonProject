# Azure IP流量分析工具

## 概述
`query_ip_azure.sh`是一个强大的Shell脚本工具，用于全面分析Azure环境中特定IP地址的网络流量。该工具自动发现相关资源、网络安全组和流日志配置，并使用KQL查询从Log Analytics工作区中提取详细的流量数据。脚本采用Azure CLI和Azure Resource Graph实现高效的资源发现和查询。

## 前提条件
- Azure CLI (最新版本)
- jq (JSON处理工具)
- bash环境 (Linux/macOS/Windows WSL)
- 对Azure订阅的适当访问权限
  - 至少需要"读取者"角色
  - 对Log Analytics工作区的查询权限
  - 对Azure Resource Graph的查询权限

## 安装步骤
1. 下载脚本到本地目录
2. 赋予脚本执行权限
   ```bash
   chmod +x query_ip_azure.sh
   ```
3. 确保已安装依赖工具
   ```bash
   # 安装jq (Ubuntu/Debian)
   sudo apt-get install jq
   
   # 安装jq (CentOS/RHEL)
   sudo yum install jq
   
   # 安装jq (macOS)
   brew install jq
   ```
4. 确认Azure CLI已安装并已登录
   ```bash
   # 检查Azure CLI安装
   az --version
   
   # 登录Azure
   az login
   ```

## 使用方法
基本用法:
```bash
./query_ip_azure.sh <IP地址> [天数]
```

示例:
```bash
# 查询特定IP过去30天的流量日志(默认)
./query_ip_azure.sh 10.10.10.10

# 查询特定IP过去60天的流量日志
./query_ip_azure.sh 10.10.10.10 60
```

## 功能详解

### 1. 全面的资源发现
- 自动检查所有可用的Azure订阅
- 发现所有Log Analytics工作区
- 检查Network Watcher状态
- 识别与目标IP相关的NSG和流日志配置

### 2. 多维度数据收集
- 从所有相关工作区收集网络流量数据
- 查询与目标IP相关的安全事件
- 收集流量统计和分析数据
- 支持内部IP和外部IP地址

### 3. 深度分析功能
- 流量方向分析(入站/出站)
- 协议和端口使用情况统计
- 对端IP地址分析
- 时间序列流量模式识别
- 安全事件关联分析

### 4. 资源关联分析
- 使用Azure Resource Graph识别与IP相关的网络接口
- 自动发现关联的虚拟机和公共IP地址
- 分析与IP相关的NSG规则
- 收集虚拟机详细信息(操作系统类型、名称等)

## 输出说明
脚本执行后会创建一个输出目录，格式为`ip_traffic_<IP地址>_<时间戳>`，包含以下文件:

- `subscriptions.json`: 所有可用订阅信息
- `workspaces.json`: 发现的Log Analytics工作区
- `network_watchers.json`: Network Watcher状态
- `flow_logs.json`: 已启用的NSG流日志配置
- `network_<工作区名称>.json`: 网络流量数据
- `network_<工作区名称>.csv`: 网络流量CSV格式
- `security_<工作区名称>.json`: 安全事件数据
- `ip_stats_<工作区名称>.json`: IP统计分析
- `ip_stats_<工作区名称>.csv`: IP统计CSV格式
- `related_resources.json`: 与IP相关的网络接口资源
- `related_resources.csv`: 网络接口资源CSV格式
- `related_vms.json`: 关联的虚拟机详细信息
- `related_nsg_rules.json`: 包含目标IP的NSG规则

## 故障排除
- **Azure登录失败**: 确保您有权访问目标订阅，可能需要重新登录
- **未找到流量数据**: 检查目标IP是否正确，以及是否已配置NSG流日志
- **jq命令错误**: 确保已安装jq工具
- **权限不足**: 确保您拥有查询Log Analytics工作区和Azure Resource Graph的权限
- **查询超时**: 对于大型环境，可能需要增加查询超时时间
- **Resource Graph查询失败**: 确认Azure CLI有权限使用Azure Resource Graph

## 技术实现细节
- 发现阶段使用Azure CLI和Azure Resource Graph
- 查询阶段使用优化的KQL查询从Traffic Analytics中提取数据
- 资源关联分析使用Azure Resource Graph高效查询
- 分析阶段执行多维度统计分析
- 脚本使用颜色编码输出，提高可读性
- 实现了查询重试机制，提高可靠性

## 关键优势
- 完全基于Azure CLI，无需额外API权限
- 利用Azure Resource Graph实现高效资源发现
- 跨平台兼容(Linux/macOS/Windows WSL)
- 全自动发现和分析流程
- 多订阅和多工作区支持
- 丰富的数据输出和分析结果

---

*注意: 此脚本需要在已安装Azure CLI并登录的环境中运行。对于大型Azure环境，初次运行可能需要较长时间来发现所有资源。*