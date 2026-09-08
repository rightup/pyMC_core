# openHop Core

[![Documentation](https://img.shields.io/badge/docs-docs.openhop.dev-blue)](https://docs.openhop.dev/projects/openhop-core/)
[![PyPI](https://img.shields.io/pypi/v/openhop-core)](https://pypi.org/project/openhop-core/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**openHop Core** is a Python reimplementation of [MeshCore](https://github.com/meshcore-dev/meshcore) — a lightweight, portable C++ library for multi-hop packet routing using LoRa radios. Designed for **Raspberry Pi** and similar hardware, openHop Core communicates with LoRa modules over **SPI**.

> openHop Core is under active development. It's compatible with the original MeshCore protocol, but not yet as optimized or elegant as its C++ counterpart.

## Documentation

**Complete documentation is available at [docs.openhop.dev](https://docs.openhop.dev/projects/openhop-core/).**

### Quick Links
- [Node Usage Guide](https://docs.openhop.dev/projects/openhop-core/node-usage/) - Guide for using MeshNode
- [Examples](https://docs.openhop.dev/projects/openhop-core/examples/) - Working code examples
- [API Reference](https://docs.openhop.dev/projects/openhop-core/api-reference/) - Detailed API documentation

## Quick Start

### Installation

> **Important**: On modern Python installations (Ubuntu 22.04+, Debian 12+), you may encounter `externally-managed-environment` errors when installing packages system-wide. Create a virtual environment first:
>
> ```bash
> # Create virtual environment
> python3 -m venv openhop_env
>
> # Activate virtual environment
> # On Linux/Mac:
> source openhop_env/bin/activate
> # On Windows:
> openhop_env\Scripts\activate
> ```

```bash
# Install from PyPI
pip install openhop-core

# For hardware support (SX1262 radios)
pip install openhop-core[hardware]

# Install all dependencies
pip install openhop-core[all]
```

### Basic Usage

```python
import asyncio
from openhop_core import MeshNode, LocalIdentity
from openhop_core.hardware.sx1262_wrapper import SX1262Radio

async def main():
    # Create radio (Waveshare HAT example)
    radio = SX1262Radio(
        bus_id=0, cs_pin=21, reset_pin=18,
        busy_pin=20, irq_pin=16, txen_pin=6,
        frequency=869525000, tx_power=22
    )
    radio.begin()

    # Create mesh node
    identity = LocalIdentity()
    node = MeshNode(radio=radio, local_identity=identity)
    await node.start()

    print("Mesh node started!")

asyncio.run(main())
```

For examples, see the [documentation](https://docs.openhop.dev/projects/openhop-core/examples/).

## Hardware Support

### Supported Radios
- **Waveshare SX1262 LoRaWAN/GNSS HAT** - Popular Raspberry Pi LoRa module
- **HackerGadgets uConsole** - All-in-one extension board with LoRa support
- **FrequencyLabs meshadv-mini** - Raspberry Pi hat with E22-900M22S LoRa module

### Requirements
- Raspberry Pi (or compatible SBC)
- SX1262 LoRa module
- SPI interface enabled
- Python 3.10+

## What is MeshCore?

MeshCore enables **long-range, decentralized communication** using **multi-hop packet routing**. Devices (nodes) forward packets through neighboring nodes to reach distant ones — no central infrastructure required.

It occupies a middle ground between:

| Project | Focus |
|---------|-------|
| [Meshtastic](https://meshtastic.org/) | Casual LoRa messaging |
| [Reticulum](https://reticulum.network/) | Full encrypted networking stack |

### Use Cases
- Off-grid and emergency communication
- Tactical or field mesh deployments
- IoT mesh networks
- Remote monitoring systems

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │   MeshNode      │    │   Hardware      │
│                 │    │                 │    │                 │
│ • Text Messages │◄──►│ • Packet Routing│◄──►│ • SX1262 Radio  │
│ • Advertisements│    │ • Identity Mgmt │    │ • SPI Interface │
│ • Telemetry     │    │ • Event Service │    │ • GPIO Control  │
│ • Group Channels│    │ • Repeater Mgmt │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Security

- **Ed25519/X25519 cryptographic identities**
- **End-to-end encryption** for messages
- **CRC validation** for data integrity
- **Secure key exchange** protocols

## Project Structure

```
openHop Core/
├── src/openhop_core/          # Main package
│   ├── hardware/           # Radio hardware interfaces
│   ├── node/               # MeshNode implementation
│   ├── protocol/           # Packet protocols
│   └── events/             # Event handling
├── examples/               # Working examples
│   ├── common.py           # Shared utilities
│   ├── send_flood_advert.py
│   ├── send_direct_advert.py
│   └── ...
├── .github/workflows/      # GitHub Actions
│   └── publish-pypi.yml    # Package test and publication pipeline
└── tests/                  # Unit tests
```

## Contributing

Contributions are welcome! Please see our [contributing guide](https://docs.openhop.dev/projects/openhop-core/development/) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/openhop-dev/openhop_core.git
cd openhop_core

# Install development dependencies
pip install -e .[dev]
```



## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original [MeshCore](https://github.com/meshcore-dev/meshcore) C++ implementation
- Waveshare and HackerGadgets for hardware support

## Support

- [Documentation](https://docs.openhop.dev/projects/openhop-core/)
- [Issues](https://github.com/openhop-dev/openhop_core/issues)
- [Discussions](https://github.com/openhop-dev/openhop_core/discussions)
- [pyMC Discord](https://discord.gg/3s8MMaSTzq)
- [Meshcore Discord](https://meshcore.gg/)

---

*Built with ❤️ for mesh networking enthusiasts*</content>
