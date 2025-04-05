1# Azure IP流量分析工具

## 概述
本工具提供三个版本的脚本，用于全面分析Azure环境中特定IP地址的网络流量：
- `ip_nsg_finder.py` (Python脚本) - **最新版本**，专注于NSG发现和KQL查询
- `query_ip_azure_improved.sh` (Bash脚本) - 改进版本
- `query_ip_azure.py` (Python脚本) - 适用于无法运行Bash的环境

这些脚本采用高效的查询策略，**先定位IP相关资源和NSG，再查询关联的Log Analytics工作区**，避免遍历所有订阅和工作区，大幅提高执行效率。

## 前提条件
### 通用要求
- Azure CLI (最新版本)
- 对Azure订阅的适当访问权限
  - 至少需要"读取者"角色
  - 对Log Analytics工作区的查询权限
  - 对Azure Resource Graph的查询权限

### 最新Python脚本版本 (ip_nsg_finder.py)
- Python 3.7+
- 无需特殊的Azure SDK包，仅使用标准库和Azure CLI

### Bash脚本版本
- jq (JSON处理工具)
- bash环境 (Linux/macOS/Windows WSL)

### 旧版Python脚本版本 (query_ip_azure.py)
- Python 3.6+
- Azure SDK for Python
  - azure-identity
  - azure-mgmt-resource
  - azure-mgmt-network
  - azure-mgmt-monitor
  - azure-mgmt-loganalytics

## 安装步骤
### 最新Python脚本版本
1. 确保已安装Python 3.7+和Azure CLI
2. 下载脚本到本地目录

### Bash脚本版本
1. 下载脚本到本地目录
2. 赋予脚本执行权限
   ```bash
   chmod +x query_ip_azure_improved.sh
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

### 旧版Python脚本版本
1. 安装所需Python包
   ```bash
   pip install azure-identity azure-mgmt-resource azure-mgmt-network azure-mgmt-monitor azure-mgmt-loganalytics
   ```

## 使用方法

### 最新版Python脚本 (推荐)
```bash
# 基本用法 - 只查找与IP关联的NSG
python ip_nsg_finder.py <IP地址>

# 完整分析 - 生成KQL查询但不执行
python ip_nsg_finder.py <IP地址> --analyze

# 执行完整分析并运行KQL查询
python ip_nsg_finder.py <IP地址> --analyze --execute

# 直接指定工作区ID进行查询
python ip_nsg_finder.py <IP地址> --workspace-id <工作区ID>

# 直接查询模式 - 跳过NSG查找
python ip_nsg_finder.py <IP地址> --direct-query --workspace-id <工作区ID>

# 不使用NSG名称过滤的查询
python ip_nsg_finder.py <IP地址> --analyze --no-nsg-filter

# 指定查询时间范围（小时）
python ip_nsg_finder.py <IP地址> --time-range 48
```

### Bash脚本
```bash
./query_ip_azure_improved.sh <IP地址> [天数]
```

### 旧版Python脚本
```bash
python query_ip_azure.py <IP地址> [天数]
```

示例:
```bash
# 查询特定IP过去30天的流量日志(默认)
./query_ip_azure_improved.sh 10.10.10.10

# 使用旧版Python版本查询过去60天的流量日志
python query_ip_azure.py 10.10.10.10 60

# 使用最新版本查询并执行KQL查询
python ip_nsg_finder.py 10.10.10.10 --analyze --execute
```

## 最新版本 (ip_nsg_finder.py) 功能特点

### 主要优势
1. **无SDK依赖** - 仅依赖Azure CLI，无需安装额外的Python包
2. **智能错误恢复** - 自动修复工作区ID格式，支持多种输入格式
3. **增强型KQL引擎** - 支持带超时机制和NSG过滤开关的查询
4. **多模式查询** - 新增：
   - 直接查询模式 (--direct-query)
   - 无NSG过滤模式 (--no-nsg-filter)
   - 超时控制 (--timeout)
5. **改进的输出** - 新增查询统计文件和超时日志

### 输出内容
脚本执行后会在`output`目录中生成以下文件：

- **NSG相关信息**
  - `network_interfaces.json` - 与IP直接关联的网络接口
  - `nsg_ids.json` - 与IP关联的所有NSG ID
  - `all_subnets.json` - 所有子网信息
  - `subnet_*.json` - 特定子网的详细信息

- **流日志配置**
  - `flow_logs_config.json` - 所有NSG的流日志配置
  - `flow_logs_*.json` - 特定NSG的流日志配置
  - `workspace_ids.json` - Log Analytics工作区ID

- **KQL查询**
  - `kql_queries.json` - 所有生成的查询
  - `kql_query_*.kql` - 特定工作区的KQL查询
  - `query_results_*.json` - 查询结果

- **分析结果**
  - `analysis_results.json` - 整体分析结果摘要

## 最新版本常见问题解决

### KQL查询执行卡住
这个问题在最新版本中已修复。如果查询仍然运行缓慢：
- 尝试使用`--timeout`参数指定较短的超时时间
- 使用`--no-nsg-filter`参数可能会提高查询性能
- 确认工作区ID格式正确，可能需要删除完整资源路径

### 查询结果为空
可能的原因：
- Log Analytics工作区中没有包含目标IP的流量日志
- 日期范围内没有相关数据
- NSG流日志未正确配置或未启用

解决方法：
- 使用`--time-range`参数扩大查询时间范围
- 确保NSG已配置流日志并启用
- 尝试直接使用Azure门户验证查询

### 工作区ID格式问题
如果收到工作区ID格式错误：
- 使用`--workspace-id`参数直接指定正确的ID
- 确保提供的是工作区ID而非完整资源路径
- 如果提供了完整路径，脚本会自动提取末尾的ID部分

## Windows环境中的运行方法
在Windows系统中运行这些脚本有以下几种方式：

### 运行最新版Python脚本
直接在Windows PowerShell或命令提示符中运行：
```powershell
python C:\Users\wufei\python\pythonProject\azure\queryreport\ip_nsg_finder.py <IP地址> --analyze
```

### 运行Bash脚本
1. **使用Windows Subsystem for Linux (WSL)**
   ```powershell
   # 打开WSL
   wsl
   
   # 导航到脚本目录
   cd /mnt/c/Users/wufei/python/pythonProject/azure/queryreport/
   
   # 运行脚本
   ./query_ip_azure_improved.sh <IP地址> [天数]
   ```

2. **使用Git Bash**
   如果已安装Git for Windows，可以使用Git Bash运行脚本。

3. **使用Docker**
   ```powershell
   docker run -it --rm -v C:\Users\wufei\python\pythonProject\azure\queryreport:/data ubuntu:latest bash -c "apt update && apt install -y jq curl && curl -sL https://aka.ms/InstallAzureCLIDeb | bash && cd /data && chmod +x query_ip_azure_improved.sh && ./query_ip_azure_improved.sh <IP地址> [天数]"
   ```

### 运行旧版Python脚本
直接在Windows PowerShell或命令提示符中运行：
```powershell
python C:\Users\wufei\python\pythonProject\azure\queryreport\query_ip_azure.py <IP地址> [天数]
```

## 工作流程对比

### 最新版本 (ip_nsg_finder.py) 流程
1. **NSG发现阶段**
   - 通过Azure Resource Graph查找与目标IP关联的网络接口
   - 查找包含该IP的子网
   - 提取相关NSG

2. **流日志配置阶段**
   - 获取NSG流日志配置
   - 提取Log Analytics工作区ID

3. **KQL查询阶段**
   - 生成针对目标IP的KQL查询
   - 可选择性地执行查询
   - 汇总并保存结果

### 旧版流程
1. **资源发现阶段**
   - 查找与目标IP关联的网络接口
   - 如果没有直接相关资源，则查找包含该IP的NSG规则
   - 获取相关NSG的流日志配置

2. **数据收集阶段**
   - 查询相关NSG对应的Log Analytics工作区
   - 执行网络流量、安全事件和统计分析查询

3. **报告生成阶段**
   - 合并所有查询结果
   - 生成汇总CSV文件

## 流程图
在`mermaid.md`文件中提供了完整的流程图，展示了脚本的工作流程。

---

*注意: 这些脚本仅用于查询，不会修改Azure环境中的任何配置。*