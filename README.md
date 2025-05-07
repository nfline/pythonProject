<div align="center">

# NetSecTools

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**A Professional Network Security Automation & Monitoring Toolkit**

</div>

---

## Table of Contents

- [Overview](#overview)
- [Core Modules](#core-modules)
  - [Azure IP NSG Finder](#azure-ip-nsg-finder)
  - [ExtraHop Automation](#extrahop-automation)
  - [ThousandEyes Integration](#thousandeyes-integration)
  - [WAF Management](#waf-management)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [Development Environment](#development-environment)
- [License](#license)

---

## Overview

NetSecTools is a professional toolkit for network security engineers, focusing on cloud security, traffic analysis, automated monitoring, and security policy management. It integrates with Azure, ExtraHop, ThousandEyes, and WAF platforms, providing end-to-end automation and visibility.

---

## Core Modules

### Azure IP NSG Finder

- Automated discovery and analysis of Azure Network Security Groups (NSGs) associated with any IP address
- Flow log extraction, KQL query generation, and security event reporting
- Output in JSON and Excel for further analysis or compliance

**Key Technologies:** Azure SDK, KQL, Pandas, Excel automation

**Directory:** `azure/ip_nsg_finder/`

---

### ExtraHop Automation

- Automated device group management and tag processing for ExtraHop NPM platform
- Bulk operations with OAuth2 authentication and robust error handling
- High-performance concurrent processing for large-scale environments

**Key Technologies:** ExtraHop REST API, OAuth2, concurrent processing

**Directory:** `extrahop/`

---

### ThousandEyes Integration

- Automated synchronization of ThousandEyes monitoring data to Azure
- Host discovery, performance monitoring, and Azure AD integration
- Designed for seamless cloud monitoring and data-driven decision making

**Key Technologies:** ThousandEyes API, Azure Storage, Python automation

**Directory:** `ThousandEyes/`

---

### WAF Management

- Automated management of Web Application Firewall (WAF) policies and endpoints
- Application list retrieval, endpoint configuration, IP protection, and cipher suite updates
- Bulk and scriptable operations for large-scale web security management

**Key Technologies:** WAF API, Python scripting, batch automation

**Directory:** `waf/`

---

## Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd NetSecTools

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your API keys and credentials
```

---

## Usage Examples

### 1. Azure IP NSG Finder

```bash
az login
python -m azure.ip_nsg_finder.main --ip <target_IP_address> --time-range 24 --verbose
```

### 2. ExtraHop Device Group Management

```bash
python extrahop/device-group.py
```

### 3. ThousandEyes Data Synchronization

```bash
export THOUSANDEYES_TOKEN="your_token"
export AZURE_STORAGE_CONNECTION_STRING="your_connection_string"
python ThousandEyes/1000eyes_sync_azure.py
```

### 4. WAF Application List Retrieval

```bash
python waf/get_application_list.py
```

---

## Development Environment

- Python 3.8+
- OS: Windows, macOS, Linux
- API access required: Azure, ExtraHop, ThousandEyes, WAF

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built for network security professionals to enhance efficiency and visibility**

</div>
</div>