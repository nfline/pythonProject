# Azure IP流量分析工具

## 概述
本工具提供两个版本的脚本，用于全面分析Azure环境中特定IP地址的网络流量：
- `query_ip_azure_improved.sh` (Bash脚本) - 改进版本
- `query_ip_azure.py` (Python脚本) - 适用于无法运行Bash的环境

这些脚本采用高效的查询策略，**先定位IP相关资源和NSG，再查询关联的Log Analytics工作区**，避免遍历所有订阅和工作区，大幅提高执行效率。

## 前提条件
### Bash脚本版本
- Azure CLI (最新版本)
- jq (JSON处理工具)
- bash环境 (Linux/macOS/Windows WSL)

### Python脚本版本
- Python 3.6+
- Azure SDK for Python
  - azure-identity
  - azure-mgmt-resource
  - azure-mgmt-network
  - azure-mgmt-monitor
  - azure-mgmt-loganalytics

### 共同要求
- 对Azure订阅的适当访问权限
  - 至少需要"读取者"角色
  - 对Log Analytics工作区的查询权限
  - 对Azure Resource Graph的查询权限

## 安装步骤
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

### Python脚本版本
1. 安装所需Python包
   ```bash
   pip install azure-identity azure-mgmt-resource azure-mgmt-network azure-mgmt-monitor azure-mgmt-loganalytics
   ```

## 使用方法
### Bash脚本
```bash
./query_ip_azure_improved.sh <IP地址> [天数]
```

### Python脚本
```bash
python query_ip_azure.py <IP地址> [天数]
```

示例:
```bash
# 查询特定IP过去30天的流量日志(默认)
./query_ip_azure_improved.sh 10.10.10.10

# 使用Python版本查询过去60天的流量日志
python query_ip_azure.py 10.10.10.10 60
```

## Windows环境中的运行方法
在Windows系统中运行这些脚本有以下几种方式：

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

### 运行Python脚本
直接在Windows PowerShell或命令提示符中运行：
```powershell
python C:\Users\wufei\python\pythonProject\azure\queryreport\query_ip_azure.py <IP地址> [天数]
```

## 工作流程
改进版脚本采用以下流程：

1. **资源发现阶段**
   - 先使用Azure Resource Graph查找与目标IP关联的网络接口
   - 如果没有直接相关资源，则查找包含该IP的NSG规则
   - 获取相关NSG的流日志配置

2. **数据收集阶段**
   - 仅查询相关NSG对应的Log Analytics工作区
   - 执行网络流量、安全事件和统计分析查询

3. **报告生成阶段**
   - 合并所有查询结果
   - 生成汇总CSV文件

## 输出说明
脚本执行后会创建一个输出目录，格式为`ip_traffic_<IP地址>_<时间戳>`，包含以下文件：

- `associated_resources.json`: 与IP直接关联的资源
- `related_nsg_rules.json`: 包含该IP的NSG规则
- `flow_logs.json`: 相关NSG的流日志配置
- `target_workspaces.json`: 需要查询的目标工作区
- `network_traffic_*.json`: 网络流量数据
- `network_traffic_*.csv`: 网络流量CSV格式
- `security_events_*.json`: 安全事件数据
- `ip_stats_*.json`: IP统计分析
- `ip_stats_*.csv`: IP统计CSV格式
- `all_network_traffic.csv`: 汇总的网络流量数据

## 改进的优势
1. **更高效的查询策略**
   - 不再遍历所有订阅和工作区
   - 只查询与目标IP相关的资源和日志
   - 执行时间从数小时缩短到几分钟

2. **更精准的结果**
   - 减少了无关数据
   - 结果更加聚焦于目标IP

3. **减少权限问题**
   - 避免尝试访问无权限的订阅
   - 减少因权限不足导致的错误

## 故障排除
- **Azure登录失败**: 确保您有权访问目标订阅，可能需要重新登录
- **未找到流量数据**: 检查目标IP是否正确，以及是否已配置NSG流日志
- **jq命令错误**: 确保已安装jq工具
- **Python依赖错误**: 确保已安装所有必要的Python包

## 流程图
在`mermid.md`文件中提供了完整的流程图，展示了改进版脚本的工作流程。

---

*注意: 这些脚本仅用于查询，不会修改Azure环境中的任何配置。*