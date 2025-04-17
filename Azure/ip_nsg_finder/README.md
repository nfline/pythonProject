# IP NSG Finder 工具

## 简介
IP NSG Finder是一个强大的工具，用于查找与特定IP地址相关联的Azure网络安全组(NSG)，并分析其流日志数据。该工具通过模块化设计提供了完整的分析流程，从 IP 地址查询到 NSG 流日志分析，并生成详细的报告。

## 文件结构

```
ip_nsg_finder/
├── common.py         # 公共工具函数、常量和辅助类
├── find_nsgs.py      # 步骤1-2：查找与IP关联的NSG
├── flow_logs.py      # 步骤4-5：获取NSG流日志配置和Log Analytics工作区
├── logging_utils.py  # 日志相关工具函数
├── kql_query.py      # KQL查询相关功能
├── analyzer.py       # 主分析功能
├── main.py           # 主程序入口和参数处理
└── README.md         # 使用说明文档（本文件）
```

## 各模块功能说明

1. **common.py**: 包含通用工具函数和常量，如彩色输出、命令执行、JSON保存等
2. **find_nsgs.py**: 实现步骤1-2，根据IP查找相关的网络接口和NSG
3. **flow_logs.py**: 实现步骤4-5，获取NSG流日志配置和Log Analytics工作区信息
4. **logging_utils.py**: 日志配置和处理功能
5. **kql_query.py**: 生成并执行KQL查询，处理查询结果
6. **analyzer.py**: 整合各模块，协调完整的分析流程
7. **main.py**: 程序入口，命令行参数处理

## 功能特点
- 根据IP地址查找关联的网络接口和NSG
- 使用 Azure Resource Graph 查询流日志配置和资源
- 提取Log Analytics工作区信息
- 生成并执行KQL查询
- 将结果保存为JSON和Excel格式的报告
- 完整的日志记录功能，便于调试和审计

## 使用方法

1. 确保已安装并登录Azure CLI
2. 安装所需依赖：`pip install pandas`
3. 从命令行运行：

```bash
# 到项目根目录
python -m ip_nsg_finder.main --ip <目标IP地址> [--time-range <小时数>] [--verbose]
```

参数说明：
- `--ip` 或 `-i`: 要分析的目标IP地址（必需）
- `--time-range` 或 `-t`: 查询流日志的时间范围（小时数，默认为24）
- `--verbose` 或 `-v`: 启用详细输出

## 分析流程

工具按以下步骤执行分析：

1. 使用 Resource Graph 查询符合IP地址的网络接口
2. 提取直接关联的NSG和子网ID
3. 使用 `az network vnet subnet show` 获取子网关联的NSG
4. 使用 Resource Graph 查询NSG流日志配置
5. 提取流日志工作区ID和状态
6. 构建KQL查询，包括IP过滤条件和时间范围
7. 执行查询并将结果保存为JSON和Excel格式

## 输出文件

分析结果和中间文件将保存在当前目录下的`output`目录中，包括：

- **网络接口信息**: `network_interfaces_{IP}.json`
- **子网信息**: `subnet_{SUBNET_NAME}_{IP}.json`
- **NSG ID 列表**: `nsg_ids_found_{IP}.json`
- **流日志配置**: `flow_logs_{NSG_NAME}_{IP}.json`
- **流日志配置汇总**: `flow_logs_config_all_{IP}.json`
- **查询结果**: 
  - JSON: `flow_logs_query_results_{NSG_NAME}_{IP}.json`
  - Excel: `flow_logs_query_results_{NSG_NAME}_{IP}.xlsx`
- **日志文件**: `logs/query_log_{IP}_{DATE}.log`

## 手动验证

我们提供了详细的手动验证指南，可以帮助用户逐步验证工具的每个环节。详见 `manual_validation_guide.md` 文件。
