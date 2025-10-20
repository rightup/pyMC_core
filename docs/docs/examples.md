# Examples

This section contains practical examples of using pyMC_Core for mesh communications.

## PyMC Core Examples

This directory contains examples for using PyMC Core functionality. More examples will be added over time.

## Files

- `common.py`: Shared utilities and mock implementations used by all examples
- `send_flood_advert.py`: Flood advertisement example
- `send_direct_advert.py`: Direct advertisement example
- `send_tracked_advert.py`: Tracked advertisement example
- `ping_repeater_trace.py`: Trace ping example for repeater diagnostics

## Shared Components (`common.py`)

### `MockLoRaRadio`
Mock radio implementation for testing and demonstration:
- Simulates LoRa hardware without requiring actual hardware
- Logs transmission operations
- Returns realistic RSSI/SNR values
- Implements the `LoRaRadio` interface

### `create_mesh_node(node_name)`
Helper function that creates a mesh node setup:
- Generates a new `LocalIdentity` with cryptographic keypair
- Creates and initializes a `MockLoRaRadio`
- Returns configured `MeshNode` and `LocalIdentity`

### `print_packet_info(packet, description)`
Utility for logging packet information:
- Displays packet size, route type, and payload type
- Consistent formatting across examples

## Advertisement Examples

### `send_flood_advert.py`
Example showing how to create and broadcast a flood advertisement packet.
- Uses shared `create_mesh_node()` helper from `common.py`
- Builds a flood advert with location and flags
- Sends the packet through the mesh node's dispatcher
- Demonstrates the workflow from setup to transmission

### `send_direct_advert.py`
Example showing how to create and send a direct advertisement packet.
- Uses shared `create_mesh_node()` helper from `common.py`
- Builds a direct advert with location and flags
- Sends the packet through the mesh node's dispatcher
- Demonstrates the workflow from setup to transmission

### `ping_repeater_trace.py`
Example showing how to ping a repeater using trace packets for network diagnostics.
- Uses shared `create_mesh_node()` helper from `common.py`
- Creates a trace packet with routing to a specific repeater
- Demonstrates both basic ping and callback-based response handling
- Shows how to set up direct routing paths for targeted packets
- Includes placeholder repeater hash (replace with actual repeater's public key hash)

## Running the Examples

All examples use SX1262 LoRa radio hardware with support for multiple radio types.

### Direct Execution (Recommended)

Run the example scripts directly with optional radio type selection:

```bash
# Run examples with default Waveshare radio
python examples/send_flood_advert.py
python examples/send_direct_advert.py
python examples/send_text_message.py
python examples/send_channel_message.py
python examples/ping_repeater_trace.py
python examples/send_tracked_advert.py

# Run examples with uConsole radio
python examples/send_flood_advert.py uconsole
python examples/send_direct_advert.py uconsole
python examples/send_text_message.py uconsole
```

Each example script accepts an optional radio type parameter:
- `waveshare` (default) - Waveshare SX1262 HAT
- `uconsole` - HackerGadgets uConsole
- `meshadv-mini` - FrequencyLabs meshadv-mini

You can also run examples directly with command-line arguments:

```bash
# Default Waveshare HAT configuration
python examples/send_flood_advert.py

# uConsole configuration
python examples/send_flood_advert.py uconsole
```

### Command Line Options

Each example accepts an optional radio type parameter:

- `waveshare` (default): Waveshare LoRaWAN/GNSS HAT configuration
- `uconsole`: HackerGadgets uConsole configuration
- `meshadv-mini`: Frequency Labs Mesh Adv

```bash
# Examples with explicit radio type
python examples/send_flood_advert.py waveshare
python examples/send_flood_advert.py uconsole
python examples/send_flood_advert.py meshadv-mini
```

## Hardware Requirements

### Supported SX1262 Radio Hardware

pyMC_Core supports multiple SX1262-based LoRa radio modules:

#### Waveshare LoRaWAN/GNSS HAT
- **Hardware**: Waveshare SX1262 LoRa HAT
- **Platform**: Raspberry Pi (or compatible single-board computer)
- **Frequency**: 868MHz (EU) or 915MHz (US)
- **TX Power**: Up to 22dBm
- **SPI Bus**: SPI0
- **GPIO Pins**: CS=21, Reset=18, Busy=20, IRQ=16

#### HackerGadgets uConsole
- **Hardware**: uConsole RTL-SDR/LoRa/GPS/RTC/USB Hub
- **Platform**: Clockwork uConsole (Raspberry Pi CM4/CM5)
- **Frequency**: 433/915MHz (configurable)
- **TX Power**: Up to 22dBm
- **SPI Bus**: SPI1
- **GPIO Pins**: CS=-1, Reset=25, Busy=24, IRQ=26
- **Additional Setup**: Requires SPI1 overlay and GPS/RTC configuration (see uConsole setup guide)

#### Frequency Labs meshadv-mini
- **Hardware**: FrequencyLabs meshadv-mini Hat
- **Platform**: Raspberry Pi (or compatible single-board computer)
- **Frequency**: 868MHz (EU) or 915MHz (US)
- **TX Power**: Up to 22dBm
- **SPI Bus**: SPI0
- **GPIO Pins**: CS=8, Reset=24, Busy=20, IRQ=16

### Default Pin Configurations

#### Waveshare HAT
- SPI Bus: 0
- CS ID: 0
- CS Pin: GPIO 21
- Reset Pin: GPIO 18
- Busy Pin: GPIO 20
- IRQ Pin: GPIO 16
- TX Enable: GPIO 6
- RX Enable: Not used (-1)

#### uConsole
- SPI Bus: 1
- CS ID: 0
- CS Pin: -1
- Reset Pin: GPIO 25
- Busy Pin: GPIO 24
- IRQ Pin: GPIO 26
- TX Enable: Not used (-1)
- RX Enable: Not used (-1)

#### meshadv-mini (Frequency Labs)
- SPI Bus: 0
- CS ID: 0
- CS Pin: GPIO 8
- Busy Pin: GPIO 20
- Reset Pin: GPIO 24
- IRQ Pin: GPIO 16
- TX Enable: Not used (-1)
- RX Enable: GPIO 12

## Dependencies

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

### Core Dependencies
```bash
pip install pymc_core
```

### Hardware Dependencies (for SX1262 radio)
```bash
pip install pymc_core[hardware]
# or manually:
pip install gpiozero lgpio
```

### All Dependencies
```bash
pip install pymc_core[all]
```

## Hardware Setup

1. Connect SX1262 module to Raspberry Pi GPIO pins according to the pin configuration
2. Install required Python packages
3. Run any example to test the setup

The examples will automatically initialize the radio with the default configuration and send packets.

## Key Concepts

- **Flood Advert**: Broadcast to all nodes in the mesh network
- **Direct Advert**: Sent to a specific contact
- **Tracked Advert**: Advertisement with location tracking information
- **LocalIdentity**: Contains the node's cryptographic identity (public/private keypair)
- **MockLoRaRadio**: Mock radio implementation for testing and demonstration
- **MeshNode**: Main node class that coordinates radio, dispatcher, and identity
- **PacketBuilder**: Factory for creating different types of packets
- **Dispatcher**: Handles packet transmission and reception through the radio
- **Constants**: Use proper constants from `pymc_core.protocol.constants` instead of hardcoded values

## Configuration

All examples use hardcoded values:
- Node names: "MyNode", "TrackedNode"
- Locations: San Francisco, New York City, and London coordinates
- Flags: `ADVERT_FLAG_IS_CHAT_NODE`, `ADVERT_FLAG_HAS_LOCATION` (imported from constants)
- Radio: SX1262 with default configuration

Modify the values in the example files or `common.py` as needed for your use case.

## Radio Configuration

All examples use the SX1262 LoRa radio with the following default settings:

### Waveshare HAT Configuration
- **Radio Type**: SX1262 direct hardware control
- **Frequency**: 869.525MHz (European standard)
- **TX Power**: 22dBm
- **Spreading Factor**: 11
- **Bandwidth**: 250kHz
- **Coding Rate**: 4/5
- **Preamble Length**: 17 symbols
- **SPI Bus**: 0
- **CS Pin**: GPIO 21
- **Reset Pin**: GPIO 18
- **Busy Pin**: GPIO 20
- **IRQ Pin**: GPIO 16
- **TX Enable**: GPIO 6
- **RX Enable**: Not used (-1)

### uConsole Configuration
- **Radio Type**: SX1262 direct hardware control
- **Frequency**: 915MHz (US standard, adjust for region)
- **TX Power**: 22dBm
- **Spreading Factor**: 11
- **Bandwidth**: 250kHz
- **Coding Rate**: 4/5
- **Preamble Length**: 17 symbols
- **SPI Bus**: 1
- **CS Pin**: Not used (-1)
- **Reset Pin**: GPIO 25
- **Busy Pin**: GPIO 24
- **IRQ Pin**: GPIO 26
- **TX Enable**: Not used (-1)
- **RX Enable**: Not used (-1)

#### meshadv-mini (Frequency Labs)
- **Radio Type**: SX1262 direct hardware control
- **Frequency**: 869.525MHz (European standard)
- **TX Power**: 22dBm
- **Spreading Factor**: 11
- **Bandwidth**: 250kHz
- **Coding Rate**: 4/5
- **Preamble Length**: 17 symbols
- **SPI Bus**: 0
- **CS Pin**: GPIO 8
- **Reset Pin**: GPIO 24
- **Busy Pin**: GPIO 20
- **IRQ Pin**: GPIO 16
- **TX Enable**: Not used (-1)
- **RX Enable**: GPIO 12

The radio configuration is hardcoded in `common.py` for simplicity and reliability.

## Hardware Setup

### Raspberry Pi with Waveshare HAT
1. Connect Waveshare SX1262 HAT to Raspberry Pi 40PIN GPIO header
2. Enable SPI interface in Raspberry Pi configuration (raspi-config)
3. Install required GPIO library: `sudo apt install python3-rpi.lgpio`
4. Remove old GPIO library if present: `sudo apt remove python3-rpi.gpio`
5. The configuration is pre-set in `common.py` for the Waveshare HAT

### Raspberry Pi with Frequency Labs meshadv-mini
1. Connect Frequency Labs meshadv-mini HAT to Raspberry Pi 40PIN GPIO header
2. Enable SPI interface in Raspberry Pi configuration (raspi-config)
3. Install required GPIO library: `sudo apt install python3-rpi.lgpio`
4. Remove old GPIO library if present: `sudo apt remove python3-rpi.gpio`
5. The configuration is pre-set in `common.py` for the meshadv-mini

### Clockwork uConsole
1. The uConsole has the SX1262 radio pre-integrated
2. Enable SPI1 in `/boot/firmware/config.txt`:
   ```
   dtparam=spi=on
   dtoverlay=spi1-1cs
   ```
3. If using Rex Bookworm image, stop the devterm-printer service:
   ```bash
   sudo systemctl stop devterm-printer.service
   sudo systemctl disable devterm-printer.service
   ```
4. Connect LoRa antenna to the "LoRa" IPEX connector
5. The configuration is pre-set in `common.py` for the uConsole

## Sending Messages

```python
import asyncio
from pymc_core import MeshNode, LocalIdentity
from pymc_core.protocol.packet_builder import PacketBuilder
from pymc_core.protocol.constants import PacketType

async def send_message_example():
    # Setup node (same as above)
    node = MeshNode(radio=radio, local_identity=identity)
    await node.start()

    # Create a destination address (example)
    destination = bytes.fromhex("0123456789abcdef")

    # Create a data packet
    message = b"Hello, mesh network!"
    packet = PacketBuilder.build_data_packet(
        destination=destination,
        payload=message
    )

    # Send the packet
    await node.send_packet(packet)
    print("Message sent!")

    await node.stop()

asyncio.run(send_message_example())
```

## Packet Handling

```python
from pymc_core.node import Dispatcher
from pymc_core.protocol.packet_filter import PacketFilter

class MessageHandler:
    def __init__(self, local_identity):
        self.filter = PacketFilter(local_identity)

    async def handle_packet(self, packet):
        if not self.filter.validate_packet(packet):
            print("Invalid packet received")
            return

        if packet.packet_type == PacketType.DATA:
            message = packet.payload.decode('utf-8')
            print(f"Received: {message}")
        elif packet.packet_type == PacketType.ACK:
            print("Acknowledgment received")

# Register handler with dispatcher
dispatcher = Dispatcher()
handler = MessageHandler(identity)
dispatcher.register_handler(PacketType.DATA, handler.handle_packet)
```

## Hardware Configuration

### SX1262 LoRa Radio

```python
from pymc_core.hardware import SX1262Radio

# SX1262 radio configuration with required parameters
radio = SX1262Radio(
    bus_id=0,
    cs_id=0,
    cs_pin=21,  # Waveshare HAT CS pin
    reset_pin=18,
    busy_pin=20,
    irq_pin=16,
    txen_pin=-1,
    rxen_pin=-1,
    frequency=int(869.525 * 1000000),  # MHz to Hz
    tx_power=22,  # 22dBm
    spreading_factor=11,
    bandwidth=int(250 * 1000),  # kHz to Hz
    coding_rate=5,
    preamble_length=17
)

# Configure for mesh communication
radio.set_mesh_mode(True)
radio.enable_encryption(True)
```
## Advanced Usage

### Custom Packet Types

```python
from pymc_core.protocol.packet import Packet
from pymc_core.protocol.constants import PacketType

# Define custom packet type
CUSTOM_TYPE = 0x10

# Create custom packet
custom_packet = Packet(
    source=identity.public_key,
    destination=destination,
    payload=custom_data,
    packet_type=CUSTOM_TYPE,
    ttl=32
)

await node.send_packet(custom_packet)
```
