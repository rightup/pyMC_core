# MeshNode Usage Guide

The `MeshNode` class is the primary interface for interacting with a mesh network in pyMC_Core. This guide provides examples and explanations of how to use the MeshNode class for various mesh operations.

## Prerequisites

> **Important**: Before running examples, ensure you have pyMC_Core installed. On modern Python installations (Ubuntu 22.04+, Debian 12+), you may encounter `externally-managed-environment` errors when installing packages system-wide. Create a virtual environment first:
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
>
> # Install pyMC_Core
> pip install pymc_core[hardware]
> ```

## Available Examples

This guide references working examples from the `examples/` directory:

- **`send_flood_advert.py`**: Broadcast advertisement packets to the entire mesh network
- **`send_direct_advert.py`**: Send advertisement packets to specific contacts
- **`send_tracked_advert.py`**: Send advertisements with location tracking information
- **`send_text_message.py`**: Send encrypted text messages with CRC validation
- **`send_channel_message.py`**: Send messages to group channels
- **`ping_repeater_trace.py`**: Network diagnostics using trace packets

All examples use the `common.py` utilities for shared setup and support both Waveshare HAT and uConsole radio configurations.

### Running Examples

```bash
# Run examples directly with default Waveshare radio
python examples/send_flood_advert.py
python examples/send_direct_advert.py
python examples/send_text_message.py

# Run examples with uConsole radio
python examples/send_flood_advert.py uconsole
python examples/send_direct_advert.py uconsole
python examples/send_text_message.py uconsole
```

## Radio Setup

pyMC_Core supports multiple LoRa radio hardware configurations. Below are the setup instructions for supported devices.

### Waveshare LoRaWAN/GNSS HAT

The Waveshare HAT is a popular SX1262-based LoRa module for Raspberry Pi with official documentation available at [Waveshare Wiki](https://www.waveshare.com/wiki/SX1262_XXXM_LoRaWAN/GNSS_HAT).

**Hardware Setup:**
1. Connect the HAT to Raspberry Pi 40PIN GPIO header
2. Ensure SPI interface is enabled in Raspberry Pi configuration
3. Install required GPIO library: `sudo apt install python3-rpi.lgpio`

**Pin Configuration (Raspberry Pi):**
- SPI Bus: SPI0 (MOSI, MISO, SCLK pins)
- CS: GPIO 21
- Reset: GPIO 18
- Busy: GPIO 20
- IRQ (DIO1): GPIO 16
- TXEN: GPIO 6
- RXEN: Connected to DIO2 (not used directly)

```python
from pymc_core.hardware.sx1262_wrapper import SX1262Radio

# Waveshare HAT configuration (matches official pinout)
radio = SX1262Radio(
    bus_id=0,           # SPI bus 0
    cs_id=0,            # SPI chip select 0
    cs_pin=21,          # CS pin (GPIO 21)
    reset_pin=18,       # Reset pin (GPIO 18)
    busy_pin=20,        # Busy pin (GPIO 20)
    irq_pin=16,         # Interrupt pin (GPIO 16)
    txen_pin=6,         # TX enable pin (GPIO 6)
    rxen_pin=-1,        # RX enable (-1, connected to DIO2)
    frequency=869525000, # 869.525 MHz (EU standard)
    tx_power=22,        # 22 dBm
    spreading_factor=11, # Spreading factor
    bandwidth=250000,   # 250 kHz
    coding_rate=5,      # 4/5 coding rate
    preamble_length=17  # Preamble length
)

# Initialize the radio
radio.begin()
```

### Hacker Gadgets uConsole RTL-SDR/LoRa/GPS/RTC/USB Hub All-In-One Extension Board

The all-in-one extension board with SX1262 LoRa support.

**Prerequisites:**
- Enable SPI1 in `/boot/firmware/config.txt`:
  ```
  dtparam=spi=on
  dtoverlay=spi1-1cs
  ```
- If using Rex Bookworm image, stop the devterm-printer service:
  ```bash
  sudo systemctl stop devterm-printer.service
  sudo systemctl disable devterm-printer.service
  ```

```python
from pymc_core.hardware.sx1262_wrapper import SX1262Radio

# uConsole configuration
radio = SX1262Radio(
    bus_id=1,           # SPI bus 1
    cs_id=0,            # SPI chip select 0
    cs_pin=-1,          # Hardware CS
    reset_pin=25,       # Reset pin (GPIO 25)
    busy_pin=24,        # Busy pin (GPIO 24)
    irq_pin=26,         # Interrupt pin (GPIO 26)
    txen_pin=-1,        # TX enable (-1 if not used)
    rxen_pin=-1,        # RX enable (-1 if not used)
    frequency=915000000, # 915 MHz (US standard, adjust for your region)
    tx_power=22,        # 22 dBm
    spreading_factor=11, # Spreading factor
    bandwidth=250000,   # 250 kHz
    coding_rate=5,      # 4/5 coding rate
    preamble_length=17  # Preamble length
)

# Initialize the radio
radio.begin()
```

### Alternative Radio Configuration

For custom hardware setups, you can customize the pin configuration:

```python
# Custom pin configuration
radio = SX1262Radio(
    cs_pin=21,          # Your CS pin
    reset_pin=18,       # Your reset pin
    busy_pin=20,        # Your busy pin
    irq_pin=16,         # Your interrupt pin
    txen_pin=6,         # TX enable pin (if used)
    rxen_pin=-1,        # RX enable pin (-1 if not used)
    frequency=868000000, # 868 MHz
    tx_power=20         # 20 dBm
)
radio.begin()
```

### Radio Configuration Parameters

| Parameter | Description | Waveshare HAT | uConsole |
|-----------|-------------|---------------|----------|
| `bus_id` | SPI bus ID | 0 | 1 |
| `cs_id` | SPI chip select ID | 0 | 0 |
| `cs_pin` | Chip select GPIO pin | 21 | -1 |
| `reset_pin` | Reset GPIO pin | 18 | 25 |
| `busy_pin` | Busy GPIO pin | 20 | 24 |
| `irq_pin` | Interrupt GPIO pin | 16 | 26 |
| `txen_pin` | TX enable GPIO pin | 6 | -1 |
| `rxen_pin` | RX enable GPIO pin | -1 | -1 |
| `frequency` | Operating frequency in Hz | 869525000 (EU) | 915000000 (US) |
| `tx_power` | Transmit power in dBm | 22 | 22 |
| `spreading_factor` | LoRa spreading factor (7-12) | 11 | 11 |
| `bandwidth` | Bandwidth in Hz | 250000 | 250000 |
| `coding_rate` | Coding rate (5=4/5, 6=4/6, etc.) | 5 | 5 |
| `preamble_length` | Preamble length | 17 | 17 |

**Note:** Adjust the `frequency` parameter based on your regional LoRa regulations (868MHz for EU, 915MHz for US, 433MHz for Asia).

### Creating a MeshNode Instance

```python
import asyncio
from pymc_core.node.node import MeshNode
from pymc_core.protocol.identity import LocalIdentity

async def create_mesh_node():
    # Create local identity (generates new keys if none provided)
    identity = LocalIdentity()

    # Create mesh node with radio interface
    node = MeshNode(
        radio=radio,  # Your initialized radio instance
        local_identity=identity,
        config={
            "node": {
                "name": "MyMeshNode"
            }
        }
    )

    # Start the node
    await node.start()
    return node

# Usage
node = asyncio.run(create_mesh_node())
```

## Sending Messages

### Direct Text Messages

See the working example in `examples/send_text_message.py`:

```python
# Key excerpt from send_text_message.py
packet, crc = PacketBuilder.create_text_message(
    contact=mock_contact,
    local_identity=identity,
    message="Hello from PyMC Core! This is a test message",
    attempt=0,
    message_type="flood"
)
```

### Flood Routing Messages

See the working example in `examples/send_flood_advert.py`:

```python
# Key excerpt from send_flood_advert.py
advert_packet = PacketBuilder.create_flood_advert(
    local_identity=identity,
    name="MyNode",
    lat=37.7749,    # San Francisco latitude
    lon=-122.4194,  # San Francisco longitude
    flags=ADVERT_FLAG_IS_CHAT_NODE
)
```

## Group Communication

### Channel Messages

See the working example in `examples/send_channel_message.py` for sending messages to group channels.

### Direct Advertisements

See the working example in `examples/send_direct_advert.py` for sending advertisements to specific contacts.

## Telemetry Operations

Telemetry functionality is available in the MeshNode API but examples are not yet available in the examples folder. Refer to the API documentation for telemetry methods like `send_telemetry_request()`.

## Repeater Management

### Connecting to a Repeater

```python
async def connect_to_repeater():
    result = await node.send_login(
        repeater_name="repeater_01",
        password="secure_password"
    )

    if result["success"]:
        print("Successfully logged into repeater")
        if result.get("is_admin"):
            print("Admin privileges granted")
    else:
        print(f"Login failed: {result.get('error')}")
```

### Sending Commands to Repeater

```python
async def send_repeater_command():
    result = await node.send_repeater_command(
        repeater_name="repeater_01",
        command="status",
        parameters=None
    )

    if result["success"]:
        print(f"Repeater response: {result['response']}")
    else:
        print(f"Command failed: {result.get('error')}")
```

### Protocol Requests

```python
async def send_protocol_request():
    # Send custom protocol command
    result = await node.send_protocol_request(
        repeater_name="repeater_01",
        protocol_code=0x10,  # Custom command code
        data=b"configuration_data"
    )

    if result["success"]:
        print(f"Protocol response: {result['response']}")
    else:
        print(f"Protocol request failed: {result.get('error')}")
```

### Disconnecting from Repeater

```python
async def disconnect_from_repeater():
    result = await node.send_logout(repeater_name="repeater_01")

    if result["success"]:
        print("Successfully logged out from repeater")
    else:
        print(f"Logout failed: {result.get('error')}")
```

## Network Diagnostics

### Sending Trace Packets

See the working example in `examples/ping_repeater_trace.py` for sending trace packets to test network connectivity and repeater diagnostics.

```python
# Key excerpt from ping_repeater_trace.py
trace_packet = PacketBuilder.create_trace_packet(
    local_identity=identity,
    contact=contact,
    tag=0x12345678,
    auth_code=0xABCD,
    flags=0x01
)
```

## Event Handling

### Setting Up Event Service

```python
from pymc_core.node.events import EventService

# Create event service
event_service = EventService()

# Attach to node
node.set_event_service(event_service)

# Listen for mesh events
async def handle_mesh_events():
    async for event in event_service.listen():
        if event.type == "message_received":
            print(f"New message from {event.data.get('sender')}")
        elif event.type == "node_discovered":
            print(f"New node discovered: {event.data.get('node_id')}")
        elif event.type == "telemetry_received":
            print(f"Telemetry data received: {event.data}")

# Start event handler
asyncio.create_task(handle_mesh_events())
```

## Configuration

**Note:** Radio configuration (frequency, power, etc.) is handled when creating the `SX1262Radio` instance, not in the MeshNode config.

### Node Configuration Options

```python
config = {
    "node": {
        "name": "MyMeshNode",
        "description": "Primary mesh network node"
    },
    "network": {
        "max_hops": 5,
        "timeout": 10.0,
        "retry_count": 3
    }
}

node = MeshNode(
    radio=radio,  # Radio configured separately
    local_identity=identity,
    config=config
)
```

### Advanced Configuration

```python
# Custom logging
import logging
custom_logger = logging.getLogger("MyMeshNode")
custom_logger.setLevel(logging.DEBUG)

node = MeshNode(
    radio=radio,
    local_identity=identity,
    logger=custom_logger,
    config=config
)
```

## Error Handling

### Error Handling

```python
async def robust_send_message(contact_name: str, message: str):
    try:
        result = await node.send_text(contact_name, message)

        if result["success"]:
            print(f"Message sent successfully in {result.get('rtt_ms', 0)}ms")
            return True
        else:
            error_msg = result.get("error", "Unknown error")
            print(f"Send failed: {error_msg}")
            return False

    except RuntimeError as e:
        print(f"Contact not found: {e}")
        return False
    except asyncio.TimeoutError:
        print("Message timed out")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False
```

This guide covers the most common use cases for the MeshNode class. For detailed API documentation, refer to the [API Reference](api/node.md).
