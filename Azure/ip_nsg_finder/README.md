# IP NSG Finder 工具

## 简介
这个工具用于查找与特定IP地址相关联的Azure网络安全组(NSG)，并分析其流日志。工具将原始脚本分解为多个模块，便于维护和调试。

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

## 使用方法

1. 确保已安装并登录Azure CLI
2. 安装所需依赖：`pip install pandas`
3. 从命令行运行：

```
python -m azure.ip_nsg_finder.main --ip <目标IP地址> [--time-range <小时数>] [--verbose]
```

参数说明：
- `--ip` 或 `-i`: 要分析的目标IP地址（必需）
- `--time-range` 或 `-t`: 查询流日志的时间范围（小时数，默认为24）
- `--verbose` 或 `-v`: 启用详细输出

## 分析流程

工具按以下步骤执行分析：

1. 根据IP查找关联的网络接口
2. 检查这些网络接口关联的子网
3. 获取NSG流日志配置
4. 提取Log Analytics工作区信息
5. 针对每个NSG执行KQL查询
6. 将结果保存为JSON和Excel格式

## 输出

分析结果和中间文件将保存在当前目录下的`output`目录中，包括：
- NSG信息
- 流日志配置
- 工作区映射
- 查询结果（JSON和Excel格式）
- 日志文件（在`logs`子目录）
