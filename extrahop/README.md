# ExtraHop 工具集

## 简介

这个目录包含与 ExtraHop 网络监控和分析平台交互的自动化工具。ExtraHop 是一种网络性能监控和诊断解决方案，通过这些工具，您可以自动化管理设备组、标签和其他 ExtraHop 平台功能，提高网络监控效率。

## 文件结构

```
extrahop/
├── device-group.py     # 设备组管理工具
└── tag.py              # 设备标签管理工具
```

## 功能特点

### 设备组管理 (device-group.py)

这个脚本用于批量更新 ExtraHop 设备组的过滤规则，主要功能包括：

- 使用 OAuth2 认证与 ExtraHop API 进行安全通信
- 从 Excel 文件读取设备信息（标签、名称、IP地址）
- 构建符合 ExtraHop API 要求的过滤规则
- 一次性更新设备组配置

### 标签管理 (tag.py)

这个高级脚本提供了全面的设备标签管理功能，主要特点：

- 高性能批处理：使用并发处理大量设备
- 智能批量调整：根据处理成功率动态调整批处理大小
- 内存优化：监控系统资源使用情况
- 错误恢复：包含重试逻辑和连接池管理
- 令牌缓存：减少认证请求次数
- 详细日志和统计报告：提供操作成功率和处理时间等信息

## 系统要求

- Python 3.6+
- 以下 Python 库：
  - requests
  - pandas
  - openpyxl
  - numpy
  - urllib3

## 设置与配置

### 设备组管理工具

在使用 `device-group.py` 前，需要配置以下参数：

1. 在脚本中设置您的 ExtraHop API 凭证：
   ```python
   client_id = 'your client id'
   client_secret = 'your client secret'
   token_url = 'https://[subdomain].api.cloud.extrahop.com/oauth2/token'
   api_url = 'https://[subdomain].api.cloud.extrahop.com/api/v1/devicegroups/[device-group id]'
   ```

2. 准备一个名为 `device.xlsx` 的 Excel 文件，应包含以下列：
   - `tag`：设备标签
   - `name`：设备名称
   - `ipaddr`：设备 IP 地址

### 标签管理工具

在使用 `tag.py` 前，需要配置以下参数：

1. 在脚本中设置您的 ExtraHop API 凭证：
   ```python
   HOST = ".api.cloud.extrahop.com"
   ID = "your client id"
   SECRET = "your client secret"
   EXCEL_FILE = "device.xlsx"
   ```

2. 可选：根据您的环境调整性能参数：
   ```python
   MAX_WORKERS = 20        # 并发工作线程数
   BATCH_SIZE_INITIAL = 200 # 初始批处理大小
   MAX_BATCH_SIZE = 500    # 最大批处理大小
   ```

## 使用方法

### 设备组管理

1. 配置脚本中的 API 凭证和端点
2. 准备包含设备信息的 Excel 文件
3. 运行脚本：
   ```bash
   python device-group.py
   ```

### 标签管理

1. 配置脚本中的 API 凭证
2. 准备包含设备信息的 Excel 文件
3. 运行脚本：
   ```bash
   python tag.py
   ```

## 输出结果

### 设备组管理

脚本执行后会显示：
- OAuth 令牌生成状态
- 发送到 API 的完整 JSON 请求
- API 响应状态和内容

### 标签管理

脚本执行后会输出详细的统计信息：
- 处理的设备数量
- 成功和失败的标签操作数量
- 新创建的标签数量
- 总处理时间
- 内存使用情况

## 注意事项

1. 确保您有足够的 ExtraHop API 权限
2. 处理大量设备时，注意监控系统资源使用情况
3. 在生产环境中使用前，建议先在测试环境验证脚本功能

## 故障排除

- **认证失败**：检查 client_id 和 client_secret 是否正确
- **API 端点错误**：确认 subdomain 和 device-group id 是否设置正确
- **Excel 文件错误**：确保 Excel 文件存在且包含所需列
- **内存不足**：减少 BATCH_SIZE 或 MAX_WORKERS 值

## 更新日志

- 2025-05-05：初始版本发布，包含设备组管理和标签管理功能
