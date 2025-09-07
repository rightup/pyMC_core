## pyMC_Core Documentation

Welcome to the documentation for **pyMC_Core**, the python library for Meshcore communication.

**pyMC_Core** is a Python-based reimplementation of [MeshCore](https://github.com/meshcore-dev/meshcore) — a lightweight, portable C++ library for multi-hop packet routing using LoRa radios. Designed for **Raspberry Pi** and similar hardware, pyMC_Core communicates with LoRa modules over **SPI**.

> pyMC_Core is under active development. It's compatible with the original MeshCore protocol and provides similar functionality in Python.

---

## What is MeshCore?

MeshCore enables long-range, decentralised communication using **multi-hop packet routing**. Devices (nodes) forward packets through neighbouring nodes to reach distant ones — no central infrastructure required.

It occupies a middle ground between:

| Project    | Focus                           |
| ---------- | ------------------------------- |
| Meshtastic | Casual LoRa messaging           |
| Reticulum  | Full encrypted networking stack |

Use cases:

- Off-grid and emergency communication
- Tactical or field mesh deployments
- IoT mesh networks

---


## Overview

pyMC_Core provides the fundamental building blocks for mesh network communication, including:

- **Packet Building**: Create and parse mesh network packets
- **Protocol Handling**: Manage encryption, routing, and protocol logic
- **Node Management**: Handle mesh node operations and communication
- **Hardware Integration**: Support for various radio hardware

## Installation

### Requirements

- Python 3.9 or higher
- pip package manager

### Basic Installation

Install pyMC_Core from PyPI:

```bash
pip install pymc_core
```

> **Note**: For most practical applications, you'll want to install with hardware support for radio communication:
> ```bash
> pip install pymc_core[radio,hardware]
> ```
> The base package provides protocol and packet handling capabilities, but hardware integration is required for mesh communication.

### Installation from Source

> **Important**: On modern Python installations (Ubuntu 22.04+, Debian 12+), you may encounter `externally-managed-environment` errors when installing packages system-wide. Create a virtual environment first:
>
> ```bash
> # Create virtual environment
> python3 -m venv pymc_env
>
> # Activate virtual environment
> # On Linux/Mac:
> source pymc_env/bin/activate
> # On Windows:
> pymc_env\Scripts\activate
> ```

Clone the repository and install in development mode:

```bash
git clone https://github.com/rightup/pymc_core.git
cd pymc_core
pip install -e .
```

### Optional Dependencies

Install with specific features:

```bash
# For radio hardware support
pip install pymc_core[radio]

# For GPIO and SPI hardware control
pip install pymc_core[hardware]

# For WebSocket radio support
pip install pymc_core[websocket]

# For development and testing
pip install pymc_core[dev]

# Install all optional dependencies
pip install pymc_core[all]
```

### Hardware Setup

For hardware integration, you may need additional system dependencies:

```bash
# On Raspberry Pi/Debian-based systems
sudo apt-get update
sudo apt-get install python3-dev python3-pip
```

## Quick Start

```python
from pymc_core import MeshNode, LocalIdentity

# Create a mesh node
identity = LocalIdentity()
node = MeshNode(radio=radio_device, local_identity=identity)

# Start the node
await node.start()
```

## Getting Help

-  [API Reference](api/core.md) - API documentation
-  [Examples](examples.md) - Code examples and tutorials
-  [Contributing](contributing.md) - How to contribute to the project
-  [Meshcord Discord](https://discord.com/channels/1343693475589263471/1343693475589263474) - Come chat with us

## Acknowledgements

- Thanks to [MeshCore](https://github.com/meshcore-dev) for the original C++ implementation.  
- Appreciation to **@scott_33238**, **@liamcottle**, **@recrof**, and **@cheaporeps** on Discord
  for their ongoing help and patience with my questions. 
- Waveshare LoRaRF library, modified to use modern `gpiozero` library (`DigitalInputDevice` and `DigitalOutputDevice`) for all GPIO operations, replacing legacy RPi.GPIO methods for compatibility across all recent Raspberry Pi models (Zero, 3, 4, 5)
- Contributors and third-party libraries (see `pyproject.toml`)

---
