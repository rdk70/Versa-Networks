# Network Monitor

A Python tool for monitoring network analytics data from Versa Networks devices.

## Features

- Retrieves analytics data for multiple network features (NGFW, SFW, CGNAT, SDWAN, etc.)
- Supports various query types (time series, table data, summary, etc.)
- Configurable metrics collection
- Pagination support
- Flexible date range filtering

## Prerequisites

- Python 3.7+
- `requests` library

## Installation

```bash
pip install requests
```

## Configuration

Configure the tool using the `AnalyticsConfig` class:

```python
config = AnalyticsConfig(
    tenant_name="Versa",
    feature=Feature.SDWAN,
    start_date="60minutesAgo",
    end_date="today",
    count=5,
    metrics=["delay", "fwdDelayVar", "revDelayVar"]
)
```

## Usage

```python
monitor = NetworkMonitor(base_url, username, password)
if monitor.login():
    data = monitor.get_analytics_data(site_name, config)
```

## Supported Features

- NGFW (Next Generation Firewall)
- SFW (Stateful Firewall)
- CGNAT (Carrier Grade NAT)
- SDWAN (Software Defined WAN)
- SECACC (Secure Access)
- SYSTEM (System metrics)

## Query Types

- Time Series
- Table Data
- Summary
- Map
- Info
- Stats

## Security Note

The tool disables SSL verification by default. For production use, enable proper certificate verification.