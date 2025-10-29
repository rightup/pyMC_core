#!/usr/bin/env python3
"""
Common utilities for PyMC Core examples.

This module provides shared utilities for PyMC Core examples,
including SX1262 radio setup and mesh node creation.
"""

import logging
import os
import sys

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Add the src directory to the path so we can import pymc_core
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
logger.debug(f"Added to path: {os.path.join(os.path.dirname(__file__), '..', 'src')}")

from pymc_core import LocalIdentity
from pymc_core.hardware.base import LoRaRadio
from pymc_core.node.node import MeshNode


def create_radio(radio_type: str = "waveshare", serial_port: str = "/dev/ttyUSB0") -> LoRaRadio:
    """Create a radio instance with configuration for specified hardware.

    Args:
        radio_type: Type of radio hardware ("waveshare", "uconsole", "meshadv-mini", or "kiss-tnc")
        serial_port: Serial port for KISS TNC (only used with "kiss-tnc" type)

    Returns:
        Radio instance configured for the specified hardware
    """
    logger.info(f"Creating radio for {radio_type}...")

    try:
        # Check if this is a KISS TNC configuration
        if radio_type == "kiss-tnc":
            from pymc_core.hardware.kiss_serial_wrapper import KissSerialWrapper

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

        # Direct SX1262 radio for other types
        from pymc_core.hardware.sx1262_wrapper import SX1262Radio

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
                "frequency": int(869.525 * 1000000),  # EU: 869.525 MHz
                "tx_power": 22,
                "spreading_factor": 11,
                "bandwidth": int(250 * 1000),
                "coding_rate": 5,
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
                f"Unknown radio type: {radio_type}. Use 'waveshare', 'meshadv-mini', 'uconsole', or 'kiss-tnc'"
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
    node_name: str = "ExampleNode", radio_type: str = "waveshare", serial_port: str = "/dev/ttyUSB0"
) -> tuple[MeshNode, LocalIdentity]:
    """Create a mesh node with radio.

    Args:
        node_name: Name for the mesh node
        radio_type: Type of radio hardware ("waveshare", "uconsole", "meshadv-mini", or "kiss-tnc")
        serial_port: Serial port for KISS TNC (only used with "kiss-tnc" type)

    Returns:
        Tuple of (MeshNode, LocalIdentity)
    """
    logger.info(f"Creating mesh node with name: {node_name} using {radio_type} radio")

    try:
        # Create a local identity (this generates a new keypair)
        logger.debug("Creating LocalIdentity...")
        identity = LocalIdentity()
        logger.info(f"Created identity with public key: {identity.get_public_key().hex()[:16]}...")

        # Create the radio
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
        else:
            logger.debug("Calling radio.begin()...")
            radio.begin()
            logger.info("Radio initialized successfully")

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
