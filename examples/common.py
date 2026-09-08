#!/usr/bin/env python3
"""
Common utilities for openHop Core examples.

This module provides shared utilities for openHop Core examples,
including SX1262 radio setup and mesh node creation.
"""

import logging
import os
import sys

# Set up logging
# Default to INFO to avoid extremely verbose CH341/SPI debug logs.
# Override at runtime, e.g.:
#   PYMC_LOG_LEVEL=DEBUG .venv/bin/python pyMC_core/examples/send_tracked_advert.py --radio-type ch341
_level_name = os.getenv("PYMC_LOG_LEVEL", "INFO").upper()
_level = getattr(logging, _level_name, logging.INFO)
logging.basicConfig(
    level=_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    force=True,
)
logger = logging.getLogger(__name__)

# Add the src directory to the path so we can import openhop_core
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
logger.debug(f"Added to path: {os.path.join(os.path.dirname(__file__), '..', 'src')}")

from openhop_core import LocalIdentity
from openhop_core.hardware.base import LoRaRadio
from openhop_core.node.node import MeshNode

RADIO_TYPES = [
    "waveshare",
    "uconsole",
    "meshadv-mini",
    "kiss-tnc",
    "kiss-modem",
    "ch341",
    "pinedio",
    "modem_usb",
    "modem_tcp",
    "pymc_usb",  # Compatibility alias for modem_usb.
    "pymc_tcp",  # Compatibility alias for modem_tcp.
]


def create_radio(
    radio_type: str = "waveshare",
    serial_port: str = "/dev/ttyUSB0",
) -> LoRaRadio:
    """Create a radio instance with configuration for specified hardware.

    Args:
        radio_type: Type of radio hardware. Supported values:
            "waveshare"     — Waveshare SX1262 HAT (SPI)
            "uconsole"      — uConsole LoRa module (SPI)
            "meshadv-mini"  — MeshAdv Mini (SPI)
            "kiss-tnc"      — KISS TNC over serial
            "kiss-modem"    — MeshCore KISS modem over serial
            "ch341"         — SX1262 via CH341 USB-to-SPI adapter
            "pinedio"       — Similar to CH341 but different pinout
            "modem_usb"     — openHop Modem over USB-CDC
            "modem_tcp"     — openHop Modem over Wi-Fi/TCP
            "pymc_usb"      — Compatibility alias for "modem_usb"
            "pymc_tcp"      — Compatibility alias for "modem_tcp"
        serial_port: Serial port path. Used by "kiss-tnc", "kiss-modem", and "modem_usb".

    Returns:
        Radio instance configured for the specified hardware
    """
    logger.info(f"Creating radio for {radio_type}...")

    try:
        # Check if this is a KISS TNC configuration
        if radio_type == "kiss-tnc":
            from openhop_core.hardware.kiss_serial_wrapper import KissSerialWrapper

            logger.debug("Using KISS Serial Wrapper")

            # KISS TNC configuration
            kiss_config = {
                "frequency": int(869.618 * 1000000),  # EU: 869.525 MHz
                "bandwidth": int(62.5 * 1000),  # 250 kHz
                "spreading_factor": 8,  # LoRa SF11
                "coding_rate": 8,  # LoRa CR 4/5
                "sync_word": 0x12,  # Sync word
                "power": 22,  # TX power
            }

            # Create KISS wrapper with specified port
            kiss_wrapper = KissSerialWrapper(
                port=serial_port, baudrate=115200, radio_config=kiss_config, auto_configure=True
            )

            logger.info("Created KISS Serial Wrapper")
            logger.info(
                f"Frequency: {kiss_config['frequency']/1000000:.3f}MHz, TX Power: {kiss_config['power']}dBm"
            )
            return kiss_wrapper

        # Check if this is a MeshCore KISS Modem configuration
        if radio_type == "kiss-modem":
            from openhop_core.hardware.kiss_modem_wrapper import KissModemWrapper

            logger.debug("Using MeshCore KISS Modem Wrapper")

            # MeshCore KISS Modem configuration
            # Note: Sync word is configured at firmware build time
            modem_config = {
                "frequency": int(869.618 * 1000000),  # EU: 869.618 MHz
                "bandwidth": int(62.5 * 1000),  # 62.5 kHz
                "spreading_factor": 8,  # LoRa SF8
                "coding_rate": 8,  # LoRa CR 4/8
                "power": 22,  # TX power
            }

            # Create KISS modem wrapper with specified port.
            # To enable host-side LBT (e.g. full-duplex on half-duplex link), call
            # modem_wrapper.set_lbt_enabled(True) after creation.
            modem_wrapper = KissModemWrapper(
                port=serial_port,
                baudrate=115200,
                radio_config=modem_config,
                auto_configure=True,
            )

            logger.info("Created MeshCore KISS Modem Wrapper")
            logger.info(
                f"Frequency: {modem_config['frequency']/1000000:.3f}MHz, TX Power: {modem_config['power']}dBm"
            )
            return modem_wrapper

        # Check if this is a CH341 configuration
        if radio_type in ("ch341", "pinedio"):
            from openhop_core.hardware.ch341.ch341_gpio_manager import CH341GPIOManager
            from openhop_core.hardware.lora.LoRaRF.SX126x import set_gpio_manager, set_spi_transport
            from openhop_core.hardware.sx1262_wrapper import SX1262Radio
            from openhop_core.hardware.transports.ch341_spi_transport import CH341SPITransport

            logger.debug("Using CH341 USB-to-SPI adapter")

            # Create CH341 GPIO manager and set it globally
            ch341_gpio = CH341GPIOManager(vid=0x1A86, pid=0x5512)
            set_gpio_manager(ch341_gpio)
            logger.debug("Set CH341 GPIO manager globally")

            # Create CH341 SPI transport and set it globally
            ch341_spi = CH341SPITransport(vid=0x1A86, pid=0x5512, auto_setup_gpio=False)
            set_spi_transport(ch341_spi)
            logger.debug("Set CH341 SPI transport globally")

            # NOTE: pin numbers are CH341 GPIO pin numbers, see CH341GPIOPin
            # documentation to see how that translates to CH341 pin numbers.
            if radio_type == "ch341":
                ch341_config = {
                    "bus_id": 0,  # Not used with CH341 but required parameter
                    "cs_id": 0,  # Not used with CH341 but required parameter
                    "cs_pin": 0,  # CH341 GPIO 0 for CS
                    "reset_pin": 2,  # CH341 GPIO 2 for Reset
                    "busy_pin": 4,  # CH341 GPIO 4 for Busy
                    "irq_pin": 6,  # CH341 GPIO 6 for IRQ
                    "txen_pin": -1,  # Not used
                    "rxen_pin": 1,  # CH341 GPIO 1 for RX enable
                    "frequency": int(869.618 * 1000000),  # EU: 869.618 MHz
                    "tx_power": 22,
                    "spreading_factor": 8,
                    "bandwidth": int(62.5 * 1000),
                    "coding_rate": 8,
                    "preamble_length": 17,
                    "use_dio2_rf": True,
                    "is_waveshare": False,  # Waveshare SX1262 LoRa HAT pinout
                    "use_dio3_tcxo": True,  # Enable TCXO on DIO3
                    "dio3_tcxo_voltage": 1.8,  # 1.8V TCXO
                }
            elif radio_type == "pinedio":
                # NOTE pinedio doesn't expose DIO2, therefore no control
                # over TXEN/RXEN.
                ch341_config = {
                    "bus_id": 0,  # Not used with CH341 but required parameter
                    "cs_id": 0,  # Not used with CH341 but required parameter
                    "cs_pin": 0,  # CH341 GPIO 0 for CS (handled by SPI engine)
                    "reset_pin": -1,  # reset is done via CH341 reset
                    "busy_pin": 11,  # CH341 GPIO 11 = pin 8 (BUSY/SLCT)
                    "irq_pin": 10,  # CH341 GPIO 10 = pin 7 (INT#/DIO1)
                    "txen_pin": -1,  # TXEN is done internally via MDIO2
                    "rxen_pin": -1,  # RXEN is inverse of TXEN
                    "frequency": int(869.618 * 1000000),  # EU: 869.618 MHz
                    "tx_power": 22,
                    "spreading_factor": 8,
                    "bandwidth": int(62.5 * 1000),
                    "coding_rate": 8,
                    "preamble_length": 17,
                    "use_dio2_rf": True,
                    "is_waveshare": False,  # Waveshare SX1262 LoRa HAT pinout
                    "use_dio3_tcxo": False,  # Enable TCXO on DIO3
                }

            logger.debug(f"CH341 configuration: {ch341_config}")
            radio = SX1262Radio(**ch341_config)
            logger.info("SX1262 radio created with CH341 USB adapter")
            logger.info(
                f"Frequency: {ch341_config['frequency']/1000000:.1f}MHz, TX Power: {ch341_config['tx_power']}dBm"
            )
            return radio

        # ── openHop Modem over Wi-Fi/TCP ────────────────────────
        if radio_type in ("modem_tcp", "pymc_tcp"):
            from openhop_core.hardware.tcp_radio import TCPLoRaRadio

            logger.debug("Using openHop Modem TCP transport")

            tcp_config = {
                "host": os.environ.get("MODEM_TCP_HOST", os.environ.get("PYMC_TCP_HOST", "")),
                "port": int(
                    os.environ.get("MODEM_TCP_PORT", os.environ.get("PYMC_TCP_PORT", 5055))
                ),
                "token": os.environ.get(
                    "MODEM_TCP_TOKEN", os.environ.get("PYMC_TCP_TOKEN", "")
                ),
                "connect_timeout": float(
                    os.environ.get(
                        "MODEM_TCP_CONNECT_TIMEOUT",
                        os.environ.get("PYMC_TCP_CONNECT_TIMEOUT", 5.0),
                    )
                ),
                "frequency": int(os.environ.get("LORA_FREQ", 869618000)),
                "bandwidth": int(os.environ.get("LORA_BW", 62500)),
                "spreading_factor": int(os.environ.get("LORA_SF", 8)),
                "coding_rate": int(os.environ.get("LORA_CR", 8)),
                "tx_power": int(os.environ.get("LORA_POWER", 22)),
                "sync_word": int(os.environ.get("LORA_SYNCWORD", "0x12"), 0),
                "preamble_length": int(os.environ.get("LORA_PREAMBLE", 16)),
                "lbt_enabled": True,
                "lbt_max_attempts": 5,
            }

            if not tcp_config["host"]:
                raise ValueError(
                    "modem_tcp radio requires MODEM_TCP_HOST env var — modem hostname or LAN IP. "
                    "PYMC_TCP_HOST remains available as a compatibility fallback."
                )

            radio = TCPLoRaRadio(**tcp_config)
            logger.info(
                f"openHop Modem TCP radio created at {tcp_config['host']}:{tcp_config['port']}: "
                f"{tcp_config['frequency']/1e6:.1f}MHz SF{tcp_config['spreading_factor']} "
                f"BW{tcp_config['bandwidth']/1000:.0f}kHz {tcp_config['tx_power']}dBm"
            )
            return radio

        # ── openHop Modem over USB-CDC ──────────────────────────
        if radio_type in ("modem_usb", "pymc_usb"):
            from openhop_core.hardware.usb_radio import USBLoRaRadio

            logger.debug("Using openHop Modem USB transport")

            # Default: EU/UK (Narrow), Switzerland preset
            usb_config = {
                "port": serial_port,  # e.g. /dev/ttyACM0
                "baudrate": 921600,
                "frequency": int(os.environ.get("LORA_FREQ", 869618000)),
                "bandwidth": int(os.environ.get("LORA_BW", 62500)),
                "spreading_factor": int(os.environ.get("LORA_SF", 8)),
                "coding_rate": int(os.environ.get("LORA_CR", 8)),
                "tx_power": int(os.environ.get("LORA_POWER", 22)),
                "sync_word": int(os.environ.get("LORA_SYNCWORD", "0x12"), 0),
                "preamble_length": int(os.environ.get("LORA_PREAMBLE", 16)),
                "lbt_enabled": True,
                "lbt_max_attempts": 5,
            }

            radio = USBLoRaRadio(**usb_config)
            logger.info(
                f"openHop Modem USB radio created on {serial_port}: "
                f"{usb_config['frequency']/1e6:.1f}MHz SF{usb_config['spreading_factor']} "
                f"BW{usb_config['bandwidth']/1000:.0f}kHz {usb_config['tx_power']}dBm"
            )
            return radio

        # Direct SX1262 radio for other types
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        logger.debug("Imported SX1262Radio successfully")

        # Radio configurations for different hardware
        configs = {
            "waveshare": {
                "bus_id": 0,
                "cs_id": 0,
                "cs_pin": 21,  # Waveshare HAT CS pin
                "reset_pin": 18,
                "busy_pin": 20,
                "irq_pin": 16,
                "txen_pin": 13,  # GPIO 13 for TX enable
                "rxen_pin": 12,
                "frequency": int(869.618 * 1000000),  # EU: 869.618 MHz
                "tx_power": 22,
                "spreading_factor": 8,
                "bandwidth": int(62.5 * 1000),
                "coding_rate": 8,
                "preamble_length": 17,
                "is_waveshare": True,
            },
            "uconsole": {
                "bus_id": 1,  # SPI1
                "cs_id": 0,
                "cs_pin": -1,  # Use hardware CS
                "reset_pin": 25,
                "busy_pin": 24,
                "irq_pin": 26,
                "txen_pin": -1,
                "rxen_pin": -1,
                "frequency": int(869.525 * 1000000),  # EU: 869.525 MHz
                "tx_power": 22,
                "spreading_factor": 11,
                "bandwidth": int(250 * 1000),
                "coding_rate": 5,
                "preamble_length": 17,
            },
            "meshadv-mini": {
                "bus_id": 0,
                "cs_id": 0,
                "cs_pin": 8,
                "reset_pin": 24,
                "busy_pin": 20,
                "irq_pin": 16,
                "txen_pin": -1,
                "rxen_pin": 12,
                "frequency": int(910.525 * 1000000),  # US: 910.525 MHz
                "tx_power": 22,
                "spreading_factor": 7,
                "bandwidth": int(62.5 * 1000),
                "coding_rate": 5,
                "preamble_length": 17,
            },
        }

        if radio_type not in configs:
            raise ValueError(
                f"Unknown radio type: {radio_type}. "
                "Use 'waveshare', 'meshadv-mini', 'uconsole', 'kiss-tnc', "
                "'kiss-modem', 'ch341', 'pinedio', 'modem_usb', or 'modem_tcp'"
            )

        radio_kwargs = configs[radio_type]
        logger.debug(f"Radio configuration for {radio_type}: {radio_kwargs}")
        radio = SX1262Radio(**radio_kwargs)
        logger.info(f"SX1262 radio created for {radio_type}")
        logger.info(
            f"Frequency: {radio_kwargs['frequency']/1000000:.1f}MHz, TX Power: {radio_kwargs['tx_power']}dBm"
        )
        return radio

    except Exception as e:
        logger.error(f"Failed to create SX1262 radio: {e}")
        logger.error(f"Error type: {type(e)}")
        import traceback

        logger.error(f"Traceback: {traceback.format_exc()}")
        raise


def create_mesh_node(
    node_name: str = "ExampleNode",
    radio_type: str = "waveshare",
    serial_port: str = "/dev/ttyUSB0",
    use_modem_identity: bool = False,
) -> tuple[MeshNode, LocalIdentity]:
    """Create a mesh node with radio.

    Args:
        node_name: Name for the mesh node
        radio_type: Type of radio hardware ("waveshare", "uconsole", "meshadv-mini",
                    "kiss-tnc", "kiss-modem", "ch341", "modem_usb", or "modem_tcp")
        serial_port: Serial port for KISS devices or an openHop Modem USB transport
                     (e.g. "/dev/ttyUSB0" for KISS or "/dev/ttyACM0" for a modem)
        use_modem_identity: If True and radio_type is "kiss-modem", use the modem's
                           cryptographic identity instead of generating a local one.
                           This keeps the private key secure on the modem hardware.

    Returns:
        Tuple of (MeshNode, Identity) - Identity may be LocalIdentity or ModemIdentity
    """
    logger.info(f"Creating mesh node with name: {node_name} using {radio_type} radio")

    try:
        # Create the radio first (needed for modem identity)
        logger.debug("Creating radio...")
        radio = create_radio(radio_type, serial_port)

        # Initialize radio (different methods for different types)
        if radio_type == "kiss-tnc":
            logger.debug("Connecting KISS radio...")
            if radio.connect():
                logger.info("KISS radio connected successfully")
                print(f"KISS radio connected to {serial_port}")
                if hasattr(radio, "kiss_mode_active") and radio.kiss_mode_active:
                    print("KISS mode is active")
                else:
                    print("Warning: KISS mode may not be active")
            else:
                logger.error("Failed to connect KISS radio")
                print(f"Failed to connect to KISS radio on {serial_port}")
                raise Exception(f"KISS radio connection failed on {serial_port}")
        elif radio_type == "kiss-modem":
            logger.debug("Connecting MeshCore KISS modem...")
            if radio.connect():
                logger.info("KISS modem connected successfully")
                print(f"KISS modem connected to {serial_port}")
                if hasattr(radio, "modem_version") and radio.modem_version:
                    print(f"Modem version: {radio.modem_version}")
                if hasattr(radio, "modem_identity") and radio.modem_identity:
                    print(f"Modem identity: {radio.modem_identity.hex()[:16]}...")
            else:
                logger.error("Failed to connect KISS modem")
                print(f"Failed to connect to KISS modem on {serial_port}")
                raise Exception(f"KISS modem connection failed on {serial_port}")
        elif radio_type == "ch341":
            logger.debug("Initializing CH341 radio...")
            ok = radio.begin()
            if ok is False:
                raise RuntimeError("CH341 SX1262 radio begin() returned False")
            logger.info("CH341 radio initialized successfully")
            print("CH341 USB adapter radio initialized")
        else:
            # Direct radios and openHop Modem transports all use begin().
            logger.debug("Calling radio.begin()...")
            ok = radio.begin()
            if ok is False:
                raise RuntimeError("Radio begin() returned False")
            logger.info("Radio initialized successfully")

        # Create identity - use modem identity if requested and available
        if use_modem_identity and radio_type == "kiss-modem":
            from openhop_core.protocol.modem_identity import ModemIdentity

            logger.debug("Creating ModemIdentity from KISS modem...")
            identity = ModemIdentity(radio)
            logger.info(f"Using modem identity: {identity.get_public_key().hex()[:16]}...")
            print(f"Using modem identity (private key secured on modem)")
        else:
            logger.debug("Creating LocalIdentity...")
            identity = LocalIdentity()
            logger.info(f"Created local identity: {identity.get_public_key().hex()[:16]}...")

        # Create a mesh node with the radio and identity
        config = {"node": {"name": node_name}}
        logger.debug(f"Creating MeshNode with config: {config}")
        mesh_node = MeshNode(radio=radio, local_identity=identity, config=config)
        logger.info(f"MeshNode created successfully: {node_name}")

        return mesh_node, identity

    except Exception as e:
        logger.error(f"Failed to create mesh node: {e}")
        logger.error(f"Error type: {type(e)}")
        import traceback

        logger.error(f"Traceback: {traceback.format_exc()}")
        raise


def print_packet_info(packet, description: str = "Packet"):
    """Print information about a packet.

    Args:
        packet: The packet to analyze
        description: Description of the packet for logging
    """
    try:
        raw_length = packet.get_raw_length()
        route_type = packet.get_route_type()
        payload_type = packet.get_payload_type()

        logger.info(f"{description}: {raw_length} bytes")
        logger.info(f"Route type: {route_type}")
        logger.info(f"Payload type: {payload_type}")

        # Also print to console for immediate feedback
        print(f"{description}: {raw_length} bytes")
        print(f"Route type: {route_type}")
        print(f"Payload type: {payload_type}")

    except Exception as e:
        logger.error(f"Failed to get packet info: {e}")
        print(f"Error getting packet info: {e}")
