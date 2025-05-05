<div align="center">

# NetSecTools

<hr style="height:3px;border:none;background-color:#3498db;margin:20px 0">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Network Security and Monitoring Toolkit for Network Engineers and Security Professionals**

</div>

<div align="center">

[Overview](#overview) •
[Core Modules](#core-modules) •
[Installation](#installation) •
[Usage Examples](#usage-examples) •
[License](#license)

</div>

---

## Overview

NetSecTools is a professional network security and monitoring toolkit designed to enhance network visibility, security assessment, and automation. This toolkit focuses on Azure cloud environments, network traffic analysis, web application firewall management, and advanced monitoring system integration.

<div align="center">
<table>
<tr>
<td align="center"><b>:cloud: Azure</b></td>
<td align="center"><b>:bar_chart: ExtraHop</b></td>
<td align="center"><b>:mag: ThousandEyes</b></td>
<td align="center"><b>:shield: WAF</b></td>
</tr>
<tr>
<td>
• NSG Flow Log Analysis<br>
• IP-NSG Association Search<br>
• Resource Monitoring
</td>
<td>
• Device Group Management<br>
• Bulk Tag Processing<br>
• Traffic Analysis
</td>
<td>
• Azure Data Synchronization<br>
• Host Discovery<br>
• Performance Monitoring
</td>
<td>
• Application List Management<br>
• Endpoint Configuration<br>
• IP Protection Policies<br>
• Cipher Suite Updates
</td>
</tr>
</table>
</div>

---

## Core Modules

### :cloud: Azure Module

Azure cloud environment management and monitoring tools for network security teams.

```
azure/
├── ip_nsg_finder/          # IP-based NSG query and flow analysis
│   ├── main.py             # Main program entry
│   ├── analyzer.py         # Core analysis engine
│   ├── find_nsgs.py        # NSG search functionality
│   ├── flow_logs.py        # Flow log processing
│   └── kql_query.py        # KQL query generation and execution
└── nsgv2/                  # NSG management tools (upgraded version)
```

**Key Features**:
- Automatic discovery of Network Security Groups (NSGs) associated with IP addresses
- Extraction and analysis of NSG flow log configurations
- Generation of optimized KQL queries
- Output of analysis reports in JSON and Excel formats

### :bar_chart: ExtraHop Module

Automated management tools integrating with the ExtraHop network performance monitoring platform.

```
extrahop/
├── device-group.py      # Device group management tool
├── tag.py               # Tag system management
└── README.md            # Module documentation
```

**Key Features**:
- Secure communication with ExtraHop API using OAuth2 authentication
- Bulk processing of device groups and tags
- High-performance concurrent batch processing of large device sets
- Memory optimization and error recovery mechanisms

### :mag: ThousandEyes Module

Integration with the ThousandEyes monitoring platform, enabling data synchronization and host discovery.

```
1000eyes/
├── 1000eyes_sync_azure.py  # ThousandEyes data synchronization to Azure
└── search_host.py          # Host discovery and tracking
```

**Key Features**:
- Automatic synchronization of ThousandEyes monitoring data to Azure storage
- Integration with Azure AD user management
- Host discovery and tracking capabilities

### :shield: WAF Module

Web Application Firewall management tools for configuring and monitoring WAF policies.

```
waf/
├── get_application_list.py     # Retrieve WAF application list
├── get_endpoint.py             # Get endpoint details
├── get_ip_protection.py        # IP protection policy management
├── update_endpoint_addnewcipher.py  # Add new cipher suites
└── update_endpoint_replaceexsitcipher.py  # Replace existing cipher suites
```

**Key Features**:
- Automated WAF application management
- IP protection policy configuration
- Endpoint cipher suite management
- Bulk updates and configuration adjustments

---

## Installation

```bash
# Install required dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env

# Edit .env file with necessary API keys and configurations
```

## Usage Examples

### 1. IP NSG Finder

Find Azure NSGs associated with a specific IP address and analyze flow logs.

```bash
# Login to Azure CLI
az login

# Run query analysis
python -m azure.ip_nsg_finder.main --ip <target_IP_address> --time-range 24 --verbose
```

### 2. ExtraHop Device Management

Bulk update ExtraHop device groups from tabular data.

```python
# Prepare Excel file with device information
# Run the update script
python extrahop/device-group.py
```

### 3. ThousandEyes Data Synchronization

Synchronize ThousandEyes monitoring data to Azure storage.

```python
# Set environment variables
export THOUSANDEYES_TOKEN="your_token"
export AZURE_STORAGE_CONNECTION_STRING="your_connection_string"

# Run synchronization script
python 1000eyes/1000eyes_sync_azure.py
```

### 4. WAF Management

View and manage WAF policy configurations.

```python
# Get WAF application list
python waf/get_application_list.py

# Update endpoint cipher suites
python waf/update_endpoint_addnewcipher.py
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

## Project Structure

```
NetSecTools/
├── azure/                # Azure cloud integration tools
│   ├── ip_nsg_finder/      # IP-NSG association analysis tool
│   └── nsgv2/              # NSG management tools (upgraded version)
├── extrahop/             # ExtraHop network analysis tools
├── 1000eyes/             # ThousandEyes monitoring integration
├── waf/                  # Web Application Firewall management
├── tools/                # Utility toolkit
├── housing_calculator/    # Buy vs. Rent calculator (PRACTICE PROJECT)
└── ios/                  # iOS screen time management (PRACTICE PROJECT)
```

## Development Environment

- Python 3.8+
- Compatible with Windows, macOS, and Linux
- Requires API access: ThousandEyes, ExtraHop, Azure, WAF

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built for network security professionals to enhance efficiency and visibility**

</div>