<div align="center">

# 🛡️ NetSecTools 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/nfline/pythonProject/commits/master)

**Professional network security and automation toolkit for network engineers and security professionals**

[Features](#-key-features) • 
[Structure](#-project-structure) • 
[Installation](#-installation) • 
[Usage](#-usage-examples) • 
[Modules](#-modules) • 
[Security](#-security-notes) • 
[License](#-license)

</div>

<div align="center">
<img src="https://raw.githubusercontent.com/nfline/pythonProject/assets/netsectools-banner.png" alt="NetSecTools Banner" width="850px">
</div>

## 📋 Overview

NetSecTools is a comprehensive collection of Python tools designed for network engineers, security professionals, and IT administrators. The toolkit provides solutions for network monitoring, security assessment, and automation tasks, helping you efficiently manage and secure your network infrastructure.

<div align="center">
<table>
<tr>
<td align="center"><b>🔍 Monitoring</b></td>
<td align="center"><b>🔒 Security</b></td>
<td align="center"><b>⚙️ Automation</b></td>
<td align="center"><b>☁️ Cloud</b></td>
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

## ✨ Key Features

- **Integrated Monitoring** – Connect ThousandEyes with Azure for comprehensive network visibility
- **Security Assessment** – Leverage Shodan for external attack surface mapping
- **Automation Tools** – Streamline repetitive tasks and improve operational efficiency
- **Network Analysis** – Utilize ExtraHop for deep packet inspection and analytics
- **WAF Management** – Configure and monitor web application firewalls
- **Cloud Integration** – Azure-focused tools for cloud resource management and analysis
- **Utility Scripts** – Solve common networking challenges with purpose-built tools

## 📂 Project Structure

```
netsectools/
│
├── 🔍 monitoring/           # Network monitoring tools
│   ├── 1000eyes_sync_azure.py   # ThousandEyes data synchronization
│   └── search_host.py           # Host discovery and tracking
│
├── 🔒 security/             # Security assessment tools
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
├── ⚙️ automation/           # Task automation utilities
│   ├── active_mouse.py         # Prevent system timeouts
│   └── random_ip.py            # Generate random IP addresses
│
├── ☁️ Azure/                # Azure cloud integration
│   ├── azure_traffic_analyzer.py   # Traffic analysis for Azure
│   └── README.md                   # Azure module documentation
│
└── 🛠️ tools/                # General utility scripts
    ├── gethostname.py          # Hostname resolution utility
    ├── splunk_search           # Splunk query tools
    └── url_validator.py        # URL validation and testing
```

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/nfline/pythonProject.git
cd pythonProject

# Set up a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venvScriptsactivate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your API keys and configuration
```

## 🚀 Usage Examples

### ThousandEyes Azure Synchronization

Sync monitoring data between ThousandEyes and Azure:

```python
# Set required environment variables
export THOUSANDEYES_TOKEN="your_token"
export AZURE_STORAGE_CONNECTION_STRING="your_connection_string"

# Run the synchronization
python monitoring/1000eyes_sync_azure.py
```

### Shodan Host Search

Look up host information using Shodan:

```python
# Create an Excel file with IP addresses in the first column
# Run the script to fetch host information
python security/shodan/search_host.py
```

### WAF Management

Get a list of WAF applications:

```python
# Configure your WAF credentials in .env
python security/waf/get_application_list.py
```

### Azure Traffic Analysis

Analyze Azure network traffic patterns:

```python
# Ensure Azure credentials are configured
python Azure/azure_traffic_analyzer.py
```

### URL Validation

Validate URLs from an Excel spreadsheet:

```python
# Prepare Excel file with URLs in a column named 'URL'
python tools/url_validator.py
```

## 🧩 Modules

<details>
<summary><b>🔍 Monitoring Module</b></summary>

Tools for network monitoring and performance tracking:

- **ThousandEyes Integration**: Synchronize monitoring data with Azure
- **Host Search**: Find and track network assets
</details>

<details>
<summary><b>🔒 Security Module</b></summary>

Tools for security assessment and threat detection:

- **Shodan Integration**: External attack surface mapping
- **ExtraHop Analysis**: Network traffic inspection
- **WAF Management**: Web application firewall configuration
</details>

<details>
<summary><b>⚙️ Automation Module</b></summary>

Tools to automate routine tasks:

- **Mouse Activity**: Prevent system timeouts
- **IP Generation**: Create IP addresses for testing
</details>

<details>
<summary><b>☁️ Azure Module</b></summary>

Tools for Azure cloud management:

- **Traffic Analyzer**: Monitor and analyze Azure network traffic
- **Resource Management**: Track and optimize Azure resources
</details>

<details>
<summary><b>🛠️ Utility Tools</b></summary>

General-purpose network utilities:

- **URL Validator**: Check URL accessibility
- **Hostname Resolver**: DNS and hostname utilities
- **Splunk Integration**: Query and analyze Splunk data
</details>

## 🔐 Security Notes

- Store API keys and credentials as environment variables
- Review code before executing in production environments
- Follow the principle of least privilege when configuring API access
- Regularly update dependencies to patch security vulnerabilities

## 📊 Compatibility

- Python 3.8 or higher
- Windows, macOS, and Linux compatible
- Requires appropriate API access for ThousandEyes, Shodan, Azure, and other services

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**nfline** - Network Security Engineer

[![GitHub](https://img.shields.io/badge/GitHub-nfline-181717?style=flat&logo=github)](https://github.com/nfline)

---

<div align="center">

**Made with ❤️ for network security professionals**

If you find this toolkit useful, please consider giving it a star ⭐

</div>