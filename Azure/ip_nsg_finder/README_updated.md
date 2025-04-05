# IP NSG Finder 工具

## 简介
IP NSG Finder是一个强大的工具，用于查找与特定IP地址相关联的Azure网络安全组(NSG)，并分析其流日志数据。该工具通过模块化设计提供了完整的分析流程，从IP地址查询到NSG流日志分析，并生成详细的报告。

## 功能特点
- 根据IP地址查找关联的网络接口和NSG
- 获取NSG流日志配置信息
- 提取Log Analytics工作区信息
- 生成并执行KQL查询
- 将结果保存为JSON和Excel格式的报告
- 完整的日志记录功能，便于调试和审计

## 文件结构
```
ip_nsg_finder/
├── __init__.py       # 包初始化文件
├── analyzer.py       # 主分析功能，协调整个分析流程
├── common.py         # 公共工具函数、常量和辅助类
├── find_nsgs.py      # 查找与IP关联的NSG（步骤1-2）
├── flow_logs.py      # 获取NSG流日志配置和Log Analytics工作区（步骤4-5）
├── kql_query.py      # KQL查询生成和执行功能
├── logging_utils.py  # 日志设置和管理功能
├── main.py           # 主程序入口和命令行参数处理
└── README.md         # 使用说明（本文件）
```

## 安装要求
- Python 3.6或更高版本
- Azure CLI已安装并登录
- pandas库（`pip install pandas`）

## 使用方法
1. 确保已经安装Azure CLI并成功登录：
   ```
   az login
   ```

2. 运行命令：
   ```
   python -m ip_nsg_finder.main --ip <目标IP地址> [--time-range <小时数>] [--verbose]
   ```

### 参数说明
- `--ip` 或 `-i`：要分析的目标IP地址（**必需**）
- `--time-range` 或 `-t`：查询流日志的时间范围，单位为小时（默认为24小时）
- `--verbose` 或 `-v`：启用详细输出，包括更多调试信息

## 工作流程
1. **初始化和参数处理**：解析命令行参数，设置日志
2. **查找网络接口**：根据IP查找关联的虚拟机、网络接口和公共IP地址
3. **获取NSG信息**：确定与上述资源关联的网络安全组
4. **获取流日志配置**：获取每个NSG的流日志配置信息
5. **获取工作区信息**：提取Log Analytics工作区ID
6. **生成KQL查询**：为每个NSG生成适当的KQL查询
7. **执行查询**：在相应的工作区执行查询
8. **处理结果**：将查询结果保存为JSON和Excel格式

## 输出文件
所有输出将保存在当前目录下的`output`文件夹中：
- NSG信息JSON文件
- 流日志配置JSON文件
- 工作区映射JSON文件
- 查询结果（JSON和Excel格式）
- 日志文件（在`logs`子目录中）

## 常见问题
1. **找不到任何NSG**：确认目标IP确实与Azure资源关联，且具有相应的权限
2. **没有流日志数据**：检查NSG流日志是否已启用，以及是否配置了Traffic Analytics
3. **查询超时**：对于大型Log Analytics工作区，增加查询超时参数

## 故障排除
如遇问题，请检查logs目录中的日志文件，其中包含详细的执行信息和错误消息。
您也可以使用`--verbose`选项获取更详细的控制台输出。

## 贡献
欢迎贡献代码、报告问题或提出改进建议。
