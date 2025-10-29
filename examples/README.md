# PyMC Core Examples

This directory contains examples demonstrating how to use PyMC Core with different radio hardware configurations.

## Available Examples

All examples support multiple radio types via `--radio-type` argument:

- **`send_tracked_advert.py`**: Send location-tracked advertisements
- **`send_direct_advert.py`**: Send direct advertisements without mesh routing
- **`send_text_message.py`**: Send text messages to mesh nodes
- **`send_channel_message.py`**: Send messages to specific channels
- **`ping_repeater_trace.py`**: Test mesh routing and trace packet paths

## Radio Hardware Support

### Direct Radio (SX1262)
- **waveshare**: Waveshare SX1262 HAT for Raspberry Pi
- **uconsole**: ClockworkPi uConsole LoRa module
- **meshadv-mini**: MeshAdviser Mini board

### KISS TNC
- **kiss-tnc**: Serial KISS TNC devices (MeshTNC)

## Configuration

All configurations use Hz-based frequency and bandwidth values for consistency.

### SX1262 Direct Radio Configurations

**Waveshare HAT (EU 869 MHz):**
```python
waveshare_config = {
    "bus_id": 0,                          # SPI bus
    "cs_id": 0,                           # SPI chip select
    "cs_pin": 21,                         # Waveshare HAT CS pin
    "reset_pin": 18,                      # Reset GPIO pin
    "busy_pin": 20,                       # Busy GPIO pin
    "irq_pin": 16,                        # IRQ GPIO pin
    "txen_pin": 13,                       # TX enable GPIO
    "rxen_pin": 12,                       # RX enable GPIO
    "frequency": int(869.525 * 1000000),  # 869.525 MHz in Hz
    "tx_power": 22,                       # TX power (dBm)
    "spreading_factor": 11,               # LoRa SF11
    "bandwidth": int(250 * 1000),         # 250 kHz in Hz
    "coding_rate": 5,                     # LoRa CR 4/5
    "preamble_length": 17,                # Preamble length
    "is_waveshare": True,                 # Waveshare-specific flag
}
```

**uConsole (EU 869 MHz):**
```python
uconsole_config = {
    "bus_id": 1,                          # SPI1 bus
    "cs_id": 0,                           # SPI chip select
    "cs_pin": -1,                         # Use hardware CS
    "reset_pin": 25,                      # Reset GPIO pin
    "busy_pin": 24,                       # Busy GPIO pin
    "irq_pin": 26,                        # IRQ GPIO pin
    "txen_pin": -1,                       # No TX enable pin
    "rxen_pin": -1,                       # No RX enable pin
    "frequency": int(869.525 * 1000000),  # 869.525 MHz in Hz
    "tx_power": 22,                       # TX power (dBm)
    "spreading_factor": 11,               # LoRa SF11
    "bandwidth": int(250 * 1000),         # 250 kHz in Hz
    "coding_rate": 5,                     # LoRa CR 4/5
    "preamble_length": 17,                # Preamble length
}
```

**MeshAdv Mini (US 915 MHz):**
```python
meshadv_config = {
    "bus_id": 0,                          # SPI bus
    "cs_id": 0,                           # SPI chip select
    "cs_pin": 8,                          # CS GPIO pin
    "reset_pin": 24,                      # Reset GPIO pin
    "busy_pin": 20,                       # Busy GPIO pin
    "irq_pin": 16,                        # IRQ GPIO pin
    "txen_pin": -1,                       # No TX enable pin
    "rxen_pin": 12,                       # RX enable GPIO
    "frequency": int(910.525 * 1000000),  # 910.525 MHz in Hz
    "tx_power": 22,                       # TX power (dBm)
    "spreading_factor": 7,                # LoRa SF7
    "bandwidth": int(62.5 * 1000),        # 62.5 kHz in Hz
    "coding_rate": 5,                     # LoRa CR 4/5
    "preamble_length": 17,                # Preamble length
}
```

### KISS TNC Configuration

**KISS TNC (EU 869 MHz):**
```python
kiss_config = {
    'frequency': int(869.525 * 1000000),  # 869.525 MHz in Hz
    'bandwidth': int(250 * 1000),         # 250 kHz in Hz
    'spreading_factor': 11,               # LoRa SF11
    'coding_rate': 5,                     # LoRa CR 4/5
    'sync_word': 0x12,                    # Sync word
    'power': 22                           # TX power (dBm)
}
```

## Usage Examples

### SX1262 Direct Radio
```bash
# Send tracked advert with Waveshare HAT (default)
python3 send_tracked_advert.py

# Send text message with uConsole
python3 send_text_message.py --radio-type uconsole

# Ping test with MeshAdv Mini
python3 ping_repeater_trace.py --radio-type meshadv-mini
```

### KISS TNC
```bash
# Send tracked advert via KISS TNC
python3 send_tracked_advert.py --radio-type kiss-tnc --serial-port /dev/cu.usbserial-0001

# Send text message via KISS TNC
python3 send_text_message.py --radio-type kiss-tnc --serial-port /dev/ttyUSB0

# Send direct advert via KISS TNC
python3 send_direct_advert.py --radio-type kiss-tnc --serial-port /dev/cu.usbserial-0001

# Send flood advert via KISS TNC
python3 send_flood_advert.py --radio-type kiss-tnc --serial-port /dev/ttyUSB0

# Send channel message via KISS TNC
python3 send_channel_message.py --radio-type kiss-tnc --serial-port /dev/cu.usbserial-0001

# Ping test via KISS TNC
python3 ping_repeater_trace.py --radio-type kiss-tnc --serial-port /dev/cu.usbserial-0001
```

## Common Module (`common.py`)

Provides shared utilities for examples:

- `create_radio(radio_type, serial_port)`: Create radio instances
- `create_mesh_node(name, radio_type, serial_port)`: Create mesh nodes
- `print_packet_info(packet, description)`: Debug packet information

**Supported Radio Types:**
- `waveshare`: Waveshare SX1262 HAT
- `uconsole`: ClockworkPi uConsole LoRa
- `meshadv-mini`: MeshAdviser Mini board
- `kiss-tnc`: KISS TNC devices

## Requirements

### For SX1262 Direct Radio:
- SX1262 hardware (Waveshare HAT, uConsole, MeshAdv Mini)
- SPI interface enabled on Raspberry Pi
- GPIO access for control pins
- Python SPI libraries (`pip install spidev RPi.GPIO`)

### For KISS TNC:
- KISS-compatible TNC device (MeshTNC, etc.)
- Serial/USB connection
- pyserial library (`pip install pyserial`)

## Troubleshooting

### SX1262 Radio Issues:
1. Enable SPI: `sudo raspi-config` → Interface Options → SPI
2. Check GPIO permissions: `sudo usermod -a -G gpio $USER`
3. Verify wiring matches pin configuration in `common.py`
4. Test SPI communication: `ls /dev/spi*`

### KISS TNC Issues:
1. Check device connection: `ls /dev/tty*` or `ls /dev/cu.*`
2. Verify permissions: `sudo chmod 666 /dev/ttyUSB0`
3. Ensure no other programs using port
4. Test with terminal: `screen /dev/ttyUSB0 115200`

### Import Errors:
Make sure pymc_core is properly installed:
```bash
cd ../
pip install -e .
```
