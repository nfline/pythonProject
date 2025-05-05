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
• WAF management<br>
• Network Security Group analysis
</td>
<td>
• System automation<br>
• IP address management<br>
• URL validation<br>
• Financial calculators
</td>
<td>
• Azure traffic analysis<br>
• NSG flow logs analysis<br>
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
- **:shield: Security Assessment** – Leverage Shodan for external attack surface mapping and service detection
- **:robot: Automation Tools** – Streamline repetitive tasks and improve operational efficiency
- **:bar_chart: Network Analysis** – Utilize ExtraHop for deep packet inspection and traffic analytics
- **:broom: WAF Management** – Configure and monitor web application firewalls
- **:cloud: Cloud Integration** – Azure-focused tools for cloud resource management and analysis
- **:wrench: Utility Tools** – Solve common networking challenges with purpose-built scripts
- **:house: Financial Tools** – Practice project for buy vs. rent financial comparison calculator
- **:iphone: Mobile Apps** – Practice iOS screen time management and parental control application

</div>

---

## :file_folder: Project Structure

```
netsectools/
│
├── :mag: 1000eyes/              # ThousandEyes monitoring tools
│   ├── 1000eyes_sync_azure.py   # ThousandEyes data synchronization to Azure
│   └── search_host.py           # Host discovery and tracking
│
├── :closed_lock_with_key: security/             
│   ├── extrahop/              # Network traffic analysis
│   │   ├── device-group.py      # Device grouping functionality
│   │   ├── tag.py               # ExtraHop tagging system
│   │   └── README.md            # ExtraHop module documentation
│   │
│   ├── shodan/               # Shodan API integration
│   │   ├── search_host.py       # Host information lookup
│   │   └── test.txt             # Shodan query test data
│   │
│   └── waf/                  # Web Application Firewall tools
│       ├── get_application_list.py    # List WAF applications
│       ├── get_endpoint.py            # Retrieve endpoint details
│       ├── get_ip_protection.py       # IP protection settings
│       └── update_endpoint_*.py       # Endpoint management tools
│
├── :house: housing_calculator/   # Buy vs. Rent calculator (PRACTICE PROJECT)
│   ├── app.py                 # Flask application entry
│   ├── static/                # CSS and JavaScript files
│   └── templates/             # HTML templates
│
├── :iphone: ios/                 # iOS screen time app (PRACTICE PROJECT)
│   ├── AppDelegate.swift      # Application delegate
│   ├── ScreenTimeManager.swift # Screen time management
│   ├── ParentControlViewController.swift # Parental control view
│   └── UsageReportViewController.swift  # Usage report view
│
├── :cloud: azure/                # Azure cloud integration
│   ├── ip_nsg_finder/           # IP NSG finder and flow log analysis tool
│   │   ├── main.py              # Main program entry
│   │   ├── analyzer.py          # Core analysis engine
│   │   ├── find_nsgs.py         # NSG search functionality
│   │   ├── flow_logs.py         # Flow log processing
│   │   └── kql_query.py         # KQL query generation and execution
│   └── nsgv2/                   # NSG management tools (upgraded version)
│
└── :toolbox: tools/             # General utility scripts
    ├── gethostname.py         # Hostname resolution utility
    ├── splunk search          # Splunk query tools
    └── url_validator.py       # URL validation and testing
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
python 1000eyes/1000eyes_sync_azure.py
```
</details>

<details>
<summary><b>Shodan Host Search</b></summary>

```python
# Create an Excel file with IP addresses in the first column
# Run the script to fetch host information
python shodan/search_host.py
```
</details>

<details>
<summary><b>WAF Management</b></summary>

```python
# Configure your WAF credentials in .env
python waf/get_application_list.py
```
</details>

<details>
<summary><b>Azure Traffic Analysis</b></summary>

```python
# Ensure Azure credentials are configured
python azure/azure_traffic_analyzer.py
```
</details>

<details>
<summary><b>Buy vs. Rent Calculator</b></summary>

```python
# Run the Flask web application (practice project)
python housing_calculator/app.py

# Access in browser
http://localhost:5000
```
</details>

<details>
<summary><b>IP NSG Finder</b></summary>

```bash
# Login to Azure CLI
az login

# Run the IP NSG Finder tool
python -m azure.ip_nsg_finder.main --ip <target_IP_address> [--time-range <hours>] [--verbose]
```
</details>

<details>
<summary><b>URL Validation</b></summary>

```python
# Prepare an Excel file with a column named 'URL'
python tools/url_validator.py
```
</details>

---

## :puzzle_piece: Modules

<details open>
<summary><b>:mag: ThousandEyes Monitoring Module</b></summary>

Tools for network monitoring and performance tracking:

- **ThousandEyes Integration**: Synchronize monitoring data with Azure
- **Host Search**: Find and track network assets
</details>

<details>
<summary><b>:closed_lock_with_key: Security Module</b></summary>

Tools for security assessment and threat detection:

- **Shodan Integration**: External attack surface mapping
- **ExtraHop Analysis**: Network traffic inspection and analysis
- **WAF Management**: Web application firewall configuration
- **NSG Flow Log Analysis**: Azure Network Security Group traffic analysis
</details>

<details>
<summary><b>:house: Financial Tools Module</b></summary>

(Practice project) Financial analysis and decision support tools:

- **Buy vs. Rent Calculator**: Long-term financial planning and analysis
- **Investment Return Analysis**: Comparison of different housing investment returns
</details>

<details>
<summary><b>:iphone: iOS Application Module</b></summary>

(Practice project) iOS application development:

- **Screen Time Management**: Tool based on Apple's Screen Time API
- **Parental Controls**: Application usage control for parents
- **Usage Reports**: Detailed analysis of application usage
</details>

<details>
<summary><b>:cloud: Azure Module</b></summary>

Azure cloud management tools:

- **Traffic Analyzer**: Monitor and analyze Azure network traffic
- **IP NSG Finder**: Find NSGs associated with specific IP addresses and analyze flow logs
- **Resource Management**: Track and optimize Azure resources
</details>

<details>
<summary><b>:toolbox: Utility Tools</b></summary>

General-purpose network utilities:

- **URL Validator**: Check URL accessibility
- **Hostname Resolver**: DNS and hostname tools
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
- Compatible with Windows, macOS, and Linux
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