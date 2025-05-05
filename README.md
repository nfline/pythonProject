<div align="center">

# :shield: NetSecTools :shield:

<hr style="height:3px;border:none;background-color:#3498db;margin:20px 0">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/nfline/pythonProject/commits/master)

**Professional network security and automation toolkit for network engineers and security professionals**

</div>

<div align="center">

[:clipboard: Overview](#clipboard-overview) •
[:sparkles: Features](#sparkles-key-features) •
[:file_folder: Structure](#file_folder-project-structure) •
[:wrench: Installation](#wrench-installation) •
[:rocket: Usage](#rocket-usage-examples) •
[:puzzle_piece: Modules](#puzzle_piece-modules) •
[:lock: Security](#lock-security-notes) •
[:chart_with_upwards_trend: Compatibility](#chart_with_upwards_trend-compatibility) •
[:scroll: License](#scroll-license)

</div>

---

## :clipboard: Overview

NetSecTools is a comprehensive collection of Python tools designed for network engineers, security professionals, and IT administrators. The toolkit provides solutions for network monitoring, security assessment, and automation tasks, helping you efficiently manage and secure your network infrastructure.

<div align="center">
<table>
<tr>
<td align="center"><b>:mag: Monitoring</b></td>
<td align="center"><b>:closed_lock_with_key: Security</b></td>
<td align="center"><b>:gear: Automation</b></td>
<td align="center"><b>:cloud: Cloud</b></td>
</tr>
<tr>
<td>
• ThousandEyes integration<br>
• Performance tracking<br>
• Host discovery
</td>
<td>
• Shodan API integration<br>
• ExtraHop analysis<br>
• WAF management
</td>
<td>
• System automation<br>
• IP address management<br>
• URL validation
</td>
<td>
• Azure traffic analysis<br>
• Cloud resource monitoring<br>
• Data synchronization
</td>
</tr>
</table>
</div>

---

## :sparkles: Key Features

<div>

- **:arrows_counterclockwise: Integrated Monitoring** – Connect ThousandEyes with Azure for comprehensive network visibility
- **:shield: Security Assessment** – Leverage Shodan for external attack surface mapping
- **:robot: Automation Tools** – Streamline repetitive tasks and improve operational efficiency
- **:bar_chart: Network Analysis** – Utilize ExtraHop for deep packet inspection and analytics
- **:broom: WAF Management** – Configure and monitor web application firewalls
- **:cloud: Cloud Integration** – Azure-focused tools for cloud resource management and analysis
- **:wrench: Utility Scripts** – Solve common networking challenges with purpose-built tools

</div>

---

## :file_folder: Project Structure

```
netsectools/
│
├── :mag: monitoring/           # Network monitoring tools
│   ├── 1000eyes_sync_azure.py   # ThousandEyes data synchronization
│   └── search_host.py           # Host discovery and tracking
│
├── :closed_lock_with_key: security/             # Security assessment tools
│   ├── extrahop/              # Network traffic analysis
│   │   ├── device-group.py      # Device grouping functionality
│   │   ├── tag.py               # ExtraHop tagging system
│   │   └── trigger.json         # Event trigger configuration
│   │
│   ├── shodan/               # Shodan API integration
│   │   ├── search_host.py       # Host information lookup
│   │   └── test.txt             # Test data for Shodan queries
│   │
│   └── waf/                  # Web Application Firewall tools
│       ├── get_application_list.py    # List WAF applications
│       ├── get_endpoint.py            # Retrieve endpoint details
│       ├── get_ip_protection.py       # IP protection settings
│       └── update_endpoint_*.py       # Endpoint management tools
│
├── :gear: automation/           # Task automation utilities
│   ├── active_mouse.py         # Prevent system timeouts
│   └── random_ip.py            # Generate random IP addresses
│
├── :cloud: Azure/                # Azure cloud integration
│   ├── azure_traffic_analyzer.py   # Traffic analysis for Azure
│   ├── ip_nsg_finder/           # IP NSG查找与流日志分析工具
│   │   ├── main.py              # 主程序入口
│   │   ├── analyzer.py          # 核心分析引擎
│   │   ├── find_nsgs.py         # NSG查找功能
│   │   ├── flow_logs.py         # 流日志处理
│   │   └── kql_query.py         # KQL查询生成与执行
│   └── README.md                   # Azure module documentation
│
└── :toolbox: tools/                # General utility scripts
    ├── gethostname.py          # Hostname resolution utility
    ├── splunk_search           # Splunk query tools
    └── url_validator.py        # URL validation and testing
```

---

## :wrench: Installation

```bash
# Clone the repository
git clone https://github.com/nfline/pythonProject.git
cd pythonProject

# Set up a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your API keys and configuration
```

---

## :rocket: Usage Examples

<details open>
<summary><b>ThousandEyes Azure Synchronization</b></summary>

```python
# Set required environment variables
export THOUSANDEYES_TOKEN="your_token"
export AZURE_STORAGE_CONNECTION_STRING="your_connection_string"

# Run the synchronization
python monitoring/1000eyes_sync_azure.py
```
</details>

<details>
<summary><b>Shodan Host Search</b></summary>

```python
# Create an Excel file with IP addresses in the first column
# Run the script to fetch host information
python security/shodan/search_host.py
```
</details>

<details>
<summary><b>WAF Management</b></summary>

```python
# Configure your WAF credentials in .env
python security/waf/get_application_list.py
```
</details>

<details>
<summary><b>Azure Traffic Analysis</b></summary>

```python
# Ensure Azure credentials are configured
python Azure/azure_traffic_analyzer.py
```
</details>

<details>
<summary><b>IP NSG Finder</b></summary>

```bash
# 登录Azure CLI
az login

# 运行IP NSG Finder工具
python -m ip_nsg_finder.main --ip <目标IP地址> [--time-range <小时数>] [--verbose]
```
</details>

<details>
<summary><b>URL Validation</b></summary>

```python
# Prepare Excel file with URLs in a column named 'URL'
python tools/url_validator.py
```
</details>

---

## :puzzle_piece: Modules

<details open>
<summary><b>:mag: Monitoring Module</b></summary>

Tools for network monitoring and performance tracking:

- **ThousandEyes Integration**: Synchronize monitoring data with Azure
- **Host Search**: Find and track network assets
</details>

<details>
<summary><b>:closed_lock_with_key: Security Module</b></summary>

Tools for security assessment and threat detection:

- **Shodan Integration**: External attack surface mapping
- **ExtraHop Analysis**: Network traffic inspection
- **WAF Management**: Web application firewall configuration
</details>

<details>
<summary><b>:gear: Automation Module</b></summary>

Tools to automate routine tasks:

- **Mouse Activity**: Prevent system timeouts
- **IP Generation**: Create IP addresses for testing
</details>

<details>
<summary><b>:cloud: Azure Module</b></summary>

Tools for Azure cloud management:

- **Traffic Analyzer**: Monitor and analyze Azure network traffic
- **IP NSG Finder**: 查找与特定IP关联的NSG并分析流日志数据
- **Resource Management**: Track and optimize Azure resources
</details>

<details>
<summary><b>:toolbox: Utility Tools</b></summary>

General-purpose network utilities:

- **URL Validator**: Check URL accessibility
- **Hostname Resolver**: DNS and hostname utilities
- **Splunk Integration**: Query and analyze Splunk data
</details>

---

## :lock: Security Notes

- :key: Store API keys and credentials as environment variables
- :eyes: Review code before executing in production environments
- :closed_lock_with_key: Follow the principle of least privilege when configuring API access
- :arrows_counterclockwise: Regularly update dependencies to patch security vulnerabilities

---

## :chart_with_upwards_trend: Compatibility

- Python 3.8 or higher
- Windows, macOS, and Linux compatible
- Requires appropriate API access for ThousandEyes, Shodan, Azure, and other services

---

## :scroll: License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## :bust_in_silhouette: Author

<div align="center">

**nfline** - Network Security Engineer

[![GitHub](https://img.shields.io/badge/GitHub-nfline-181717?style=flat&logo=github)](https://github.com/nfline)

</div>

---

<div align="center">

**Made with ❤️ for network security professionals**

If you find this toolkit useful, please consider giving it a star ⭐

</div>