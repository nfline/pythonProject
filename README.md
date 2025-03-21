# Network Security & Automation Tools

A professional collection of network security and automation tools.

## 🔧 Project Structure

```
pythonProject/
├── monitoring/
│   └── 1000eyes_sync_azure.py    # ThousandEyes Azure integration tool
├── security/
│   ├── extrahop/                 # ExtraHop network analysis tools
│   ├── shodan/                   # Shodan API tools
│   │   └── search_host.py        # Host information lookup tool
│   └── waf/                      # Web application firewall tools
├── automation/
│   ├── active_mouse.py          # Mouse activity automation tool
│   └── random_ip.py             # IP address generator
└── tools/                        # Utility tools
    └── url_validator.py         # URL validation tool
```

## 🚀 Main Features

### Monitoring Tools
- **ThousandEyes Integration**
  - Azure data synchronization
  - User management automation
  - Performance monitoring

- **Host Search Tools**
  - IP-based host information lookup
  - Network asset management
  - Batch host operations

### Security Tools
- **ExtraHop Tools**
  - Network traffic analysis
  - Security threat detection
  - Performance monitoring

- **Shodan Integration**
  - Asset discovery
  - Vulnerability scanning
  - Security assessment

- **WAF Management**
  - Rule configuration
  - Attack protection
  - Log analysis

### Automation Tools
- **Mouse Activity Automation**
  - System sleep prevention
  - Automated operations
  - Scheduled tasks

- **IP Tools**
  - Random IP generation
  - Address pool management
  - Network segmentation

## 📦 Installation Requirements

- Python 3.8+
- pip package manager

### Dependency Installation
```bash
pip install -r requirements.txt
```

## 🔑 Configuration Guide

### ThousandEyes Configuration
```python
# Environment variables
THOUSANDEYES_TOKEN = "your_token"
AZURE_STORAGE_CONNECTION_STRING = "your_connection_string"
TE_LOGIN_ACCOUNT_GROUP_ID = "your_login_account_group_id"
TE_ACCOUNT_GROUP_ID = "your_account_group_id"
```

### Shodan Configuration
```python
# Environment variable
SHODAN_API_KEY = "your_api_key"
```

## 📖 Usage Examples

### ThousandEyes Synchronization
```python
python monitoring/1000eyes_sync_azure.py
```

### Host Search
```python
python shodan/search_host.py --target "hostname"
```

### URL Validation
```python
python tools/url_validator.py --input "test_urls.xlsx"
```

## 🛡️ Security Notes

- All API keys and sensitive information should be managed using environment variables or configuration files
- Follow the principle of least privilege
- Regularly update dependencies to fix security vulnerabilities

## 🔄 Changelog

### 2024.03
- Optimized project structure
- Updated documentation
- Cleaned up redundant code

## 👥 Maintainer

- [@nfline](https://github.com/nfline)

## 📄 License

[MIT](LICENSE) © nfline

---

If you find this project helpful, please give it a star ⭐