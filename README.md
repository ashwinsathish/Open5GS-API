# Open5GS API

A Python API for interacting with Open5GS and UERANSIM components. This package provides comprehensive tools for managing UE configurations, network traffic analysis, and PCF configurations.

## Features

- UE Configuration Management
- Network Traffic Analysis with Wireshark Integration
- UE and UPF Operations Support
- Real-time Network Performance Metrics
- PCF Configuration Management
- Extensive Error Handling

## Quick Start

```python
from open5gsapi import open5gs

# Set configuration paths
open5gs.set_config_path('/path/to/pcf.yaml')
open5gs.set_env_path('/path/to/.env')

# Basic usage example
UE_API_URL = open5gs.ue("send")
response = open5gs.send_data(UE_API_URL, {"sensor_id": 1, "temperature": 25.5})
```

## Documentation

For detailed documentation, including:
- Complete API Reference
- Usage Examples
- Configuration Management
- Error Handling
- Network Performance Monitoring

Please visit our [Wiki](link-to-your-wiki).

## Requirements

- Python 3.7+
- Open5GS
- UERANSIM
- Wireshark (optional, for network analysis)

## Installation

```bash
pip install open5gsapi
```

## Usage

Pleas refer to the Wiki for details on internal functions
