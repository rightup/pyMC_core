#!/usr/bin/env python3
"""
Simple channel message send example: Send a message to the Public channel.

This example sends an encrypted channel message to the Public channel
that all subscribers can receive.
"""

import asyncio

from common import create_mesh_node, print_packet_info

from pymc_core.protocol import Packet
from pymc_core.protocol.packet_builder import PacketBuilder


async def send_channel_message(radio_type: str = "waveshare"):
    """Send a channel message to the Public channel."""
    print("Starting channel message send example...")

    # Create mesh node
    mesh_node, identity = create_mesh_node("ChannelSender", radio_type)

    # Initialize packet variable
    packet = Packet()

    # Public channel configuration
    channels_config = [{"name": "Public", "secret": "8b3387e9c5cdea6ac9e5edbaa115cd72"}]

    # Message to send
    message_text = "Hello Public Channel! This is a test message."
    channel_name = "Public"
    sender_name = "ChannelSender"

    print(f"Channel: {channel_name}")
    print(f"Message: {message_text}")
    print("Creating channel message packet...")

    try:
        # Create channel message packet
        packet = PacketBuilder.create_group_datagram(
            group_name=channel_name,
            local_identity=identity,
            message=message_text,
            sender_name=sender_name,
            channels_config=channels_config,
        )

        print_packet_info(packet, "Created channel message packet")
        print("Sending channel message...")

        # Send the packet (channel messages are typically broadcast)
        success = await mesh_node.dispatcher.send_packet(packet, wait_for_ack=False)

        if success:
            print("Channel message sent successfully!")
            print(f"Broadcast to channel: {channel_name}")
        else:
            print("Failed to send channel message")

    except Exception as e:
        print(f"Error: {e}")

    return packet, mesh_node


def main(radio_type: str = "waveshare"):
    """Main function for running the example."""
    print(f"Using {radio_type} radio configuration")
    try:
        packet, node = asyncio.run(send_channel_message(radio_type))
        print("Example completed")
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    import sys

    radio_type = sys.argv[1] if len(sys.argv) > 1 else "waveshare"
    main(radio_type)
