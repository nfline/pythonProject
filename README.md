<div align="center">

# NetSecTools

<img src="https://raw.githubusercontent.com/nfline/pythonProject/assets/netsectools-banner.png" alt="NetSecTools Banner" width="850px">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/nfline/pythonProject/commits/master)

**Professional network security and automation toolkit for network engineers and security professionals**

</div>

<div align="center">

[Overview](#overview) •
[Features](#key-features) •
[Structure](#project-structure) •
[Installation](#installation) •
[Usage](#usage-examples) •
[Modules](#modules) •
[Security](#security-notes) •
[Compatibility](#compatibility) •
[License](#license)

</div>

---

## Overview

NetSecTools is a comprehensive collection of Python tools designed for network engineers, security professionals, and IT administrators. The toolkit provides solutions for network monitoring, security assessment, and automation tasks, helping you efficiently manage and secure your network infrastructure.

<div align="center">
<table>
<tr>
<td align="center"><b>Monitoring</b></td>
<td align="center"><b>Security</b></td>
<td align="center"><b>Automation</b></td>
<td align="center"><b>Cloud</b></td>
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

## Key Features

<div class="features-grid">

- **Integrated Monitoring** – Connect ThousandEyes with Azure for comprehensive network visibility
- **Security Assessment** – Leverage Shodan for external attack surface mapping
- **Automation Tools** – Streamline repetitive tasks and improve operational efficiency
- **Network Analysis** – Utilize ExtraHop for deep packet inspection and analytics
- **WAF Management** – Configure and monitor web application firewalls
- **Cloud Integration** – Azure-focused tools for cloud resource management and analysis
- **Utility Scripts** – Solve common networking challenges with purpose-built tools

</div>

---

## Project Structure

```
netsectools/
│
├── monitoring/           # Network monitoring tools
│   ├── 1000eyes_sync_azure.py   # ThousandEyes data synchronization
│   └── search_host.py           # Host discovery and tracking
│
├── security/             # Security assessment tools
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
├── automation/           # Task automation utilities
│   ├── active_mouse.py         # Prevent system timeouts
│   └── random_ip.py            # Generate random IP addresses
│
├── Azure/                # Azure cloud integration
│   ├── azure_traffic_analyzer.py   # Traffic analysis for Azure
│   └── README.md                   # Azure module documentation
│
└── tools/                # General utility scripts
    ├── gethostname.py          # Hostname resolution utility
    ├── splunk_search           # Splunk query tools
    └── url_validator.py        # URL validation and testing
```

---

## Installation

<div class="code-container">

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

</div>

---

## Usage Examples

<details open>
<summary><b>ThousandEyes Azure Synchronization</b></summary>
<div class="example-container">

```python
# Set required environment variables
export THOUSANDEYES_TOKEN="your_token"
export AZURE_STORAGE_CONNECTION_STRING="your_connection_string"

# Run the synchronization
python monitoring/1000eyes_sync_azure.py
```
</div>
</details>

<details>
<summary><b>Shodan Host Search</b></summary>
<div class="example-container">

```python
# Create an Excel file with IP addresses in the first column
# Run the script to fetch host information
python security/shodan/search_host.py
```
</div>
</details>

<details>
<summary><b>WAF Management</b></summary>
<div class="example-container">

```python
# Configure your WAF credentials in .env
python security/waf/get_application_list.py
```
</div>
</details>

<details>
<summary><b>Azure Traffic Analysis</b></summary>
<div class="example-container">

```python
# Ensure Azure credentials are configured
python Azure/azure_traffic_analyzer.py
```
</div>
</details>

<details>
<summary><b>URL Validation</b></summary>
<div class="example-container">

```python
# Prepare Excel file with URLs in a column named 'URL'
python tools/url_validator.py
```
</div>
</details>

---

## Modules

<div class="modules-container">

<details open>
<summary><b>Monitoring Module</b></summary>
<div class="module-details">

Tools for network monitoring and performance tracking:

- **ThousandEyes Integration**: Synchronize monitoring data with Azure
- **Host Search**: Find and track network assets
</div>
</details>

<details>
<summary><b>Security Module</b></summary>
<div class="module-details">

Tools for security assessment and threat detection:

- **Shodan Integration**: External attack surface mapping
- **ExtraHop Analysis**: Network traffic inspection
- **WAF Management**: Web application firewall configuration
</div>
</details>

<details>
<summary><b>Automation Module</b></summary>
<div class="module-details">

Tools to automate routine tasks:

- **Mouse Activity**: Prevent system timeouts
- **IP Generation**: Create IP addresses for testing
</div>
</details>

<details>
<summary><b>Azure Module</b></summary>
<div class="module-details">

Tools for Azure cloud management:

- **Traffic Analyzer**: Monitor and analyze Azure network traffic
- **Resource Management**: Track and optimize Azure resources
</div>
</details>

<details>
<summary><b>Utility Tools</b></summary>
<div class="module-details">

General-purpose network utilities:

- **URL Validator**: Check URL accessibility
- **Hostname Resolver**: DNS and hostname utilities
- **Splunk Integration**: Query and analyze Splunk data
</div>
</details>

</div>

---

## Security Notes

<div class="security-container">

- Store API keys and credentials as environment variables
- Review code before executing in production environments
- Follow the principle of least privilege when configuring API access
- Regularly update dependencies to patch security vulnerabilities

</div>

---

## Compatibility

- Python 3.8 or higher
- Windows, macOS, and Linux compatible
- Requires appropriate API access for ThousandEyes, Shodan, Azure, and other services

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

<div align="center">

**nfline** - Network Security Engineer

[![GitHub](https://img.shields.io/badge/GitHub-nfline-181717?style=flat&logo=github)](https://github.com/nfline)

</div>

---

<div align="center">

**Made with ❤️ for network security professionals**

If you find this toolkit useful, please consider giving it a star ⭐

</div>

<style>
.features-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 10px;
}
.code-container, .example-container, .module-details, .security-container {
  background-color: #f8f8f8;
  border-radius: 5px;
  padding: 15px;
  margin: 10px 0;
}
.modules-container {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 15px;
}
details {
  margin-bottom: 15px;
}
summary {
  cursor: pointer;
  padding: 8px;
  background-color: #f0f0f0;
  border-radius: 5px;
}
</style>