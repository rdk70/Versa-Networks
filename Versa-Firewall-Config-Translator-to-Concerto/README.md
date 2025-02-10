# PAN to Versa Configuration Translator

An asynchronous Python utility for translating Palo Alto Networks (PAN) firewall configurations to Versa Networks format and uploading them to a service template via the Versa API.

---

## NOTICE!

This script attempts to convert a Palo Alto Firewall configuration as completely and acurately as possible. It is NOT going to convert perfectly, please verify everything.

---

## Table of Contents

- [PAN to Versa Configuration Translator](#pan-to-versa-configuration-translator)
  - [NOTICE!](#notice)
  - [Table of Contents](#table-of-contents)
  - [**Features**](#features)
  - [**Requirements**](#requirements)
    - [System Requirements](#system-requirements)
    - [Python Dependencies](#python-dependencies)
  - [**Recommended Tools**](#recommended-tools)
  - [**Installation**](#installation)
  - [**Configuration**](#configuration)
    - [Environment Variables](#environment-variables)
    - [YAML Configuration](#yaml-configuration)
  - [**Usage**](#usage)
  - [**Exporting PAN Configurations**](#exporting-pan-configurations)
  - [**Supported Configuration Elements**](#supported-configuration-elements)
  - [**Architecture**](#architecture)
  - [**Troubleshooting \& FAQ**](#troubleshooting--faq)
    - [Common Issues](#common-issues)
    - [Logging](#logging)
  - [**Contributing**](#contributing)
    - [Development Guidelines](#development-guidelines)
  - [**Maintainers**](#maintainers)
    - [Support](#support)

---

## **Features**

- **Asynchronous Processing**: Leverages Python's `asyncio` for high-performance processing.
- **Comprehensive XML Parsing**: Handles PAN firewall configuration files with robust parsing.
- **Intelligent Transformation**: Maps PAN configurations to Versa format seamlessly.
- **Automated API Upload**: Pushes configurations to Versa Director using REST APIs.
- **Barch Processing**: Configurable batch sizes for efficient API uploads
- **Rate Limiting**: Prevents API overload with configurable limits.
- **Error Handling**: Includes retry mechanisms for robust execution.
- **Detailed Logging**: Multi-level logging for audits and debugging.
- **Deduplication**: Detects and removes duplicate configurations automatically.

---

## **Requirements**

### System Requirements

- **Python Version**: 3.8 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Network**: Access to Versa Director

### Python Dependencies

```plaintext
requests>=2.31.0
python-dotenv>=1.0.0
PyYAML>=6.0.1
aiohttp>=3.9.1
```

---

## **Recommended Tools**

- **VS Code**: For development, with the Python extension.
- **Ruff**: For linting and maintaining code quality.
- **Source Format Information**: https://pan.dev/scm/docs/home/ then NGFW Configuration

---

## **Installation**

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## **Configuration**

### Environment Variables

Create a `.env` file in the project root with the following variables:

```env
VERSA_BASE_URL=https://your-versa-director.com
VERSA_API_BASE_URL=https://your-versa-director.com:9182
VERSA_USERNAME=your_username
VERSA_PASSWORD=your_password
VERSA_CLIENT_ID=voae_rest
VERSA_CLIENT_SECRET=your_client_secret
```

### YAML Configuration

Edit `config/config.yaml` to configure:

Inline comments in the configuration file provide detailed explanations for each line.

```yaml
files:
  # Path to the XML file to be translated.
  xml_source_file: "./Source_Files/PAN_exported_config.xml"
template:
  tenant: TenantA
  description: Template for PAN to Versa Configuration Translation
  # Create one service template or multiple
  single_template: False
  # Name of the single template (if single_template is True).
  single_template_name: TenantA-Service-Template
  # Naming format for multiple templates.
  multi_template_pre_or_postfix: postfix
  # Prefix or postfix for template names.
  multi_template_fix: DG
  # Create a separate shared template.
  create_separate_shared_template: False
logging:
  # Console logging level.
  console_level: INFO
  # File logging level.
  file_level: DEBUG
upload:
  # Requests per second to Versa Director.
  requests_per_second: 20
  # Parallel requests.
  batch_size: 100
```

## **Usage**

1. Place your PAN configuration XML file in the `Source_Files` directory
2. Update `.env` and `config/config.yaml` files as needed
3. Run the translator:

```bash
python PAN-to-Versa-Config-Translator-Async.py
```

4. Monitor the `logs` directory for detailed execution logs

## **Exporting PAN Configurations**

To export configurations:

- **From a PAN Device**: Use the GUI to save/export configurations. See the [official guide](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/firewall-administration/manage-configuration-backups/save-and-export-firewall-configurations).
- **From Panorama**: Use Panorama to save/export configurations. See the [official guide](https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/administer-panorama/manage-panorama-and-firewall-configuration-backups/save-and-export-panorama-and-firewall-configurations).

## **Supported Configuration Elements**

- **Basic Objects**
  - Addresses and address groups
  - Services and service groups
  - Applications and application groups
  - Application filters
  - Zones
  - Schedules
- **Security Policies**
  - Security rules
  - DOS rules
- **Security Profiles**
  - DOS protection profiles

## **Architecture**

```
project_root/                                 # Root directory of the project
├── PAN-to-Versa-Config-Translator.py         # Main execution script
├── .env                                      # Environment variables file
├── README.md                                 # This file
├── requirements.txt                          # Python dependencies file
├── config/                                   # Configuration file
├── src/                                      # Source code directory
│   ├── core/                                 # Core functionality modules
│   ├── parsers/                              # XML parsing modules
│   |    └──profile                           # XML parsing modules for profile elements
│   ├── transformers/                         # Data transformation modules
│   |    └──profile                           # Data transformaton modules for profile elements
│   └── utils/                                # Utilities
│       └── logger.py                         # Logging utility
├── logs/                                     # Log files
└── Source_Files/                             # PAN XML files
```

## **Troubleshooting & FAQ**

### Common Issues

1. **OAuth Token Errors**

   - Verify credentials in `.env`.
   - Check network connectivity to Versa Director.
   - Confirm API ports are open.

2. **XML Parsing Errors**

   - Ensure valid XML format and UTF-8 encoding.
   - Check file encoding (UTF-8 required).
   - Verify file permissions.

3. **Rate Limiting Issues**
   - Adjust `request_per_second` in `config.yaml`

### Logging

- Logs are stored in the `logs` directory
- Log files are named with timestamp prefix
- Console shows INFO level by default
- File logging includes DEBUG level details

## **Contributing**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/name`)
3. Commit changes (`git commit -am 'Add feature'`)
4. Push to branch (`git push origin feature/name`)
5. Create Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Include docstrings for all functions
- Add unit tests for new features
- Update documentation as needed

## **Maintainers**

- Your Name (@yourgithub)
- Support Email: rkauffman@versa-networks.com

### Support

For issues and feature requests, please:

1. Check existing GitHub issues
2. Create a new issue with:
   - Clear description
   - Steps to reproduce
   - Expected vs actual behavior
   - Logs and configuration (sanitized)
