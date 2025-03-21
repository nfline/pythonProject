# Network Security & Automation Tools

这是一个专业的网络安全和自动化工具集合，包含了多个实用的脚本和工具。

## 🔧 项目结构

```
pythonProject/
├── monitoring/
│   ├── 1000eyes_sync_azure.py    # ThousandEyes 与 Azure 同步工具
│   └── search_host.py            # 主机搜索工具
├── security/
│   ├── extrahop/                 # ExtraHop 网络分析工具
│   ├── shodan/                   # Shodan API 工具集
│   └── waf/                      # Web 应用防火墙工具
├── automation/
│   ├── active_mouse.py          # 鼠标活动自动化工具
│   └── random_ip.py             # IP 地址随机生成器
└── tools/                       # 通用工具集

```

## 🚀 主要功能

### 监控工具
- **ThousandEyes 集成**
  - Azure 同步功能
  - 自动化数据同步
  - 监控指标整合

- **主机搜索工具**
  - 快速定位目标主机
  - 网络资产管理
  - 批量主机操作

### 安全工具
- **ExtraHop 工具集**
  - 网络流量分析
  - 安全威胁检测
  - 性能监控

- **Shodan 集成**
  - 资产发现
  - 漏洞扫描
  - 安全评估

- **WAF 管理**
  - 规则配置
  - 攻击防护
  - 日志分析

### 自动化工具
- **鼠标活动自动化**
  - 防止系统休眠
  - 自动化操作
  - 定时任务

- **IP 工具**
  - 随机 IP 生成
  - 地址池管理
  - 网段划分

## 📦 安装要求

- Python 3.8+
- pip 包管理器

### 依赖安装
```bash
pip install -r requirements.txt
```

## 🔑 配置说明

### ThousandEyes 配置
```python
THOUSANDEYES_TOKEN = "your_token"
AZURE_CONNECTION_STRING = "your_connection_string"
```

### Shodan 配置
```python
SHODAN_API_KEY = "your_api_key"
```

## 📖 使用示例

### ThousandEyes 同步
```python
python monitoring/1000eyes_sync_azure.py
```

### 主机搜索
```python
python monitoring/search_host.py --target "hostname"
```

### WAF 管理
```python
python security/waf/waf_manager.py --config config.yaml
```

## 🛡️ 安全说明

- 所有 API 密钥和敏感信息请使用环境变量或配置文件管理
- 确保遵循最小权限原则
- 定期更新依赖包以修复安全漏洞

## 🔄 更新日志

### 2024.03
- 优化项目结构
- 更新文档
- 清理冗余代码

## 👥 维护者

- [@nfline](https://github.com/nfline)

## 📄 许可证

[MIT](LICENSE) © nfline

---

如果您觉得这个项目有帮助，请给它一个 star ⭐️