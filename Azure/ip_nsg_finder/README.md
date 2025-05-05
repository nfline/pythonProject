# IP NSG Finder 工具

## 简介

IP NSG Finder是一个专业的Azure网络安全分析工具，用于快速识别与特定IP地址相关联的网络安全组(NSG)，并自动分析其流日志数据。该工具采用模块化设计，提供了从IP地址查询到NSG流日志分析的完整工作流程，最终生成可视化报告，帮助管理员进行网络流量分析和安全审计。

## 文件结构

```
ip_nsg_finder/
├── __init__.py        # 包初始化文件
├── common.py          # 公共工具函数、常量和辅助类
├── find_nsgs.py       # 步骤1-2：查找与IP关联的NSG
├── flow_logs.py       # 步骤4-5：获取NSG流日志配置和Log Analytics工作区
├── logging_utils.py   # 日志相关工具函数
├── excel_utils.py     # Excel文件生成和处理工具
├── kql_query.py       # KQL查询相关功能
├── analyzer.py        # 主分析功能
├── main.py            # 主程序入口和参数处理
├── requirements.txt   # 项目依赖
├── README.md          # 使用说明文档（本文件）
├── USAGE_GUIDE.md     # 详细使用指南
├── manual_validation_guide.md # 手动验证指南
└── ip_nsg_finder_workflow.md  # 工作流程图表
```

## 各模块功能说明

1. **common.py**: 包含通用工具函数和常量，如彩色输出、命令执行、JSON保存等
2. **find_nsgs.py**: 实现步骤1-2，根据IP查找相关的网络接口和NSG
3. **flow_logs.py**: 实现步骤4-5，获取NSG流日志配置和Log Analytics工作区信息
4. **logging_utils.py**: 日志配置和处理功能
5. **excel_utils.py**: 处理Excel文件导出与格式化
6. **kql_query.py**: 生成并执行KQL查询，处理查询结果
7. **analyzer.py**: 整合各模块，协调完整的分析流程
8. **main.py**: 程序入口，命令行参数处理

## 功能特点

- 根据IP地址自动查找关联的网络接口和NSG
- 智能识别直接关联和通过子网关联的所有NSG
- 使用Azure Resource Graph高效查询流日志配置和资源
- 自动提取和验证Log Analytics工作区信息
- 根据时间范围和IP动态生成优化的KQL查询语句
- 将分析结果以多种格式导出(JSON/Excel)，支持进一步分析
- 完整的日志记录功能，便于调试和审计
- 内置错误处理和重试机制，提高工具稳定性

## 系统要求

- Python 3.6+
- Azure CLI (已安装并登录)
- 必要Python依赖包(详见requirements.txt)：
  - pandas
  - openpyxl
  - azure-identity(可选，用于更高级的身份验证)

## 安装方法

1. 克隆或下载本代码库
2. 安装所需依赖：
   ```bash
   pip install -r requirements.txt
   ```
3. 确保已安装并登录Azure CLI：
   ```bash
   az login
   ```

## 使用方法

### 基本用法

从命令行运行：

```bash
# 到项目根目录
python -m ip_nsg_finder.main --ip <目标IP地址> [--time-range <小时数>] [--verbose]
```

### 参数说明

- `--ip` 或 `-i`: 要分析的目标IP地址（必需）
- `--time-range` 或 `-t`: 查询流日志的时间范围（小时数，默认为24）
- `--verbose` 或 `-v`: 启用详细输出
- `--output-dir` 或 `-o`: 指定输出目录（默认为当前目录下的`output`文件夹）
- `--log-level` 或 `-l`: 设置日志级别（DEBUG/INFO/WARNING/ERROR，默认为INFO）

### 高级用法

详细使用说明和高级选项请参考 `USAGE_GUIDE.md` 文件。

## 分析流程

工具按以下步骤执行分析：

1. 解析命令行参数并初始化环境
2. 使用Resource Graph查询符合IP地址的网络接口
3. 提取直接关联的NSG和子网ID
4. 使用`az network vnet subnet show`获取子网关联的NSG
5. 使用Resource Graph查询NSG流日志配置
6. 提取流日志工作区ID和状态
7. 构建KQL查询，包括IP过滤条件和时间范围
8. 执行查询并将结果保存为JSON和Excel格式
9. 生成分析报告

完整工作流程图可参考 `ip_nsg_finder_workflow.md` 文件。

## 输出文件

分析结果和中间文件将保存在指定的输出目录中（默认为`output`目录），包括：

- **网络接口信息**: `network_interfaces_{IP}.json`
- **子网信息**: `subnet_{SUBNET_NAME}_{IP}.json`
- **NSG ID 列表**: `nsg_ids_found_{IP}.json`
- **流日志配置**: `flow_logs_{NSG_NAME}_{IP}.json`
- **流日志配置汇总**: `flow_logs_config_all_{IP}.json`
- **查询结果**: 
  - JSON: `flow_logs_query_results_{NSG_NAME}_{IP}.json`
  - Excel: `flow_logs_query_results_{NSG_NAME}_{IP}.xlsx`
- **日志文件**: `logs/query_log_{IP}_{DATE}.log`

## 验证与故障排除

### 手动验证

我们提供了详细的手动验证指南，可以帮助用户逐步验证工具的每个环节。详见 `manual_validation_guide.md` 文件。

### 常见问题

- **权限问题**: 确保Azure账户有足够权限访问网络资源和Log Analytics
- **未找到NSG**: 检查IP地址是否正确，以及是否与Azure资源关联
- **查询超时**: 对于大型环境，尝试减少时间范围或优化查询

## 贡献与反馈

欢迎提交问题报告和功能建议。如需贡献代码，请确保遵循项目的代码风格指南和测试要求。

## 许可证

本项目采用MIT许可证。详见LICENSE文件。

## 更新日志

- v1.0.0 (2025-05-05): 初始版本发布

