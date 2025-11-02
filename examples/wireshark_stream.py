#!/usr/bin/env python3
import argparse
import asyncio
import socket
import struct
import sys
import time

from common import create_mesh_node

LINKTYPE_USER0 = 147


def setup_wireshark_stream(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest = (ip, port)
    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_USER0)
    sock.sendto(global_hdr, dest)
    return sock, dest


class WiresharkHandler:
    def __init__(self, sock, dest):
        self.sock = sock
        self.dest = dest

    @staticmethod
    def payload_type() -> int:
        return 0xFF  # Special marker for fallback handler

    async def __call__(self, packet, metadata=None):
        try:
            raw_data = packet.get_raw_data()
            ts = time.time()
            ts_sec, ts_usec = int(ts), int((ts % 1) * 1_000_000)
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(raw_data), len(raw_data))
            self.sock.sendto(pkt_hdr + raw_data, self.dest)
            print(f"Sent {len(raw_data)} bytes to Wireshark")
        except Exception as e:
            print(f"Error handling packet: {e}")


async def main(ip, port):
    print(f"Starting Wireshark stream to {ip}:{port}...")
    sock, dest = setup_wireshark_stream(ip, port)
    print("Sent PCAP global header")

    mesh_node, identity = create_mesh_node("WiresharkStreamer")
    print("Mesh node created")

    wireshark_handler = WiresharkHandler(sock, dest)
    mesh_node.dispatcher.register_fallback_handler(wireshark_handler)
    print("Fallback handler registered")

    print("Listening for packets...")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stream mesh packets to Wireshark via UDP")
    parser.add_argument("--ip", required=True, help="Wireshark IP address")
    parser.add_argument("--port", type=int, required=True, help="Wireshark port")

    args = parser.parse_args()

    asyncio.run(main(args.ip, args.port))
