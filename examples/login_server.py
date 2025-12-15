#!/usr/bin/env python3
"""
Simple login server example: Accept and authenticate client logins.

This example demonstrates how to set up a basic authentication server
that responds to login requests from mesh clients, validates credentials,
and manages an access control list (ACL).

The server supports:
- Admin password authentication
- Guest password authentication
- ACL-based authentication (blank password)
- Automatic response to login attempts
"""

import asyncio
from typing import Dict, Optional

from common import create_mesh_node

from pymc_core.node.handlers.login_server import LoginServerHandler
from pymc_core.protocol import Identity
from pymc_core.protocol.constants import PUB_KEY_SIZE

# Permission levels
PERM_ACL_GUEST = 0x01
PERM_ACL_ADMIN = 0x02
PERM_ACL_ROLE_MASK = 0x03


class ClientInfo:
    """Represents an authenticated client in the access control list."""

    def __init__(self, identity: Identity, permissions: int = 0):
        self.id = identity
        self.permissions = permissions
        self.shared_secret = b""
        self.last_timestamp = 0
        self.last_activity = 0
        self.last_login_success = 0
        self.out_path_len = -1  # -1 means no path, need to discover
        self.out_path = bytearray()

    def is_admin(self) -> bool:
        """Check if client has admin permissions."""
        return (self.permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_ADMIN

    def is_guest(self) -> bool:
        """Check if client has guest permissions."""
        return (self.permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_GUEST


class ClientACL:
    """Access Control List for managing authenticated clients."""

    def __init__(self, max_clients: int = 32):
        self.max_clients = max_clients
        self.clients: Dict[bytes, ClientInfo] = {}  # pub_key -> ClientInfo

    def get_client(self, pub_key: bytes) -> Optional[ClientInfo]:
        """Get client by public key."""
        return self.clients.get(pub_key[:PUB_KEY_SIZE])

    def put_client(self, identity: Identity, permissions: int = 0) -> Optional[ClientInfo]:
        """Add or update client in ACL."""
        pub_key = identity.get_public_key()[:PUB_KEY_SIZE]

        if pub_key in self.clients:
            client = self.clients[pub_key]
            if permissions != 0:
                client.permissions = permissions
            return client

        if len(self.clients) >= self.max_clients:
            return None  # ACL full

        # Add new client
        client = ClientInfo(identity, permissions)
        self.clients[pub_key] = client
        return client

    def get_num_clients(self) -> int:
        """Get number of clients in ACL."""
        return len(self.clients)

    def get_all_clients(self):
        """Get all clients."""
        return list(self.clients.values())

    def remove_client(self, pub_key: bytes) -> bool:
        """Remove client from ACL."""
        key = pub_key[:PUB_KEY_SIZE]
        if key in self.clients:
            del self.clients[key]
            return True
        return False


async def run_login_server(
    radio_type: str = "waveshare",
    serial_port: str = "/dev/ttyUSB0",
    admin_password: str = "admin123",
    guest_password: str = "guest123",
):
    """
    Run a login authentication server.

    Args:
        radio_type: Radio hardware type ("waveshare", "uconsole", etc.)
        serial_port: Serial port for KISS TNC
        admin_password: Password for admin access
        guest_password: Password for guest access (empty string to disable)
    """
    print("=" * 60)
    print("PyMC Core - Login Server Example")
    print("=" * 60)
    print(f"Admin Password: {admin_password}")
    print(f"Guest Password: {guest_password if guest_password else '<disabled>'}")
    print("=" * 60)

    # Create mesh node
    mesh_node, identity = create_mesh_node("LoginServer", radio_type, serial_port)

    # Get our public key info
    our_pub_key = identity.get_public_key()
    our_hash = our_pub_key[0]
    print(f"Server Identity: {our_pub_key[:6].hex()}...")
    print(f"Server Hash: 0x{our_hash:02X}")
    print()

    # Create ACL for managing authenticated clients
    acl = ClientACL(max_clients=32)

    # Create login server handler
    login_handler = LoginServerHandler(
        local_identity=identity,
        log_fn=lambda msg: print(msg),
        acl=acl,
        admin_password=admin_password,
        guest_password=guest_password,
    )

    # Set up login event callbacks
    def on_login_success(client: ClientInfo, is_admin: bool):
        """Called when a client successfully logs in."""
        role = "ADMIN" if is_admin else "GUEST"
        pub_key_hex = client.id.get_public_key()[:6].hex()
        print(f"✓ Login Success: {pub_key_hex}... as {role}")
        print(f"  Total clients in ACL: {login_handler.get_acl().get_num_clients()}")

    def on_login_failure(sender_identity, reason: str):
        """Called when a login attempt fails."""
        pub_key_hex = sender_identity.get_public_key()[:6].hex()
        print(f"✗ Login Failed: {pub_key_hex}... - {reason}")

    login_handler.set_login_callbacks(
        on_success=on_login_success, on_failure=on_login_failure
    )

    # Set up packet sending callback
    def send_packet_with_delay(packet, delay_ms: int):
        """Send a packet with a delay."""
        asyncio.create_task(delayed_send(packet, delay_ms))

    async def delayed_send(packet, delay_ms: int):
        """Send packet after delay."""
        await asyncio.sleep(delay_ms / 1000.0)
        try:
            await mesh_node.dispatcher.send_packet(packet, wait_for_ack=False)
        except Exception as e:
            print(f"Error sending response: {e}")

    login_handler.set_send_packet_callback(send_packet_with_delay)

    # Register the handler with the dispatcher
    mesh_node.dispatcher.register_handler(LoginServerHandler.payload_type(), login_handler)

    print("Login server started and listening...")
    print("   Waiting for login requests from clients...")
    print()
    print("Commands:")
    print("  - Press Ctrl+C to stop")
    print("  - Type 'status' to show ACL status")
    print("  - Type 'list' to list authenticated clients")
    print()

    # Command processor
    async def process_commands():
        """Process user commands."""
        import sys

        loop = asyncio.get_event_loop()

        while True:
            # Check for stdin input
            try:
                if sys.stdin.readable():
                    cmd = await loop.run_in_executor(None, sys.stdin.readline)
                    cmd = cmd.strip().lower()

                    if cmd == "status":
                        acl = login_handler.get_acl()
                        print(f"\nACL Status:")
                        print(f"   Authenticated clients: {acl.get_num_clients()}/{acl.max_clients}")
                        print()

                    elif cmd == "list":
                        acl = login_handler.get_acl()
                        clients = acl.get_all_clients()
                        print(f"\n👥 Authenticated Clients ({len(clients)}):")
                        if not clients:
                            print("   <none>")
                        else:
                            for i, client in enumerate(clients, 1):
                                pub_key_hex = client.id.get_public_key()[:8].hex()
                                role = "ADMIN" if client.is_admin() else "GUEST"
                                print(f"   {i}. {pub_key_hex}... [{role}]")
                        print()

            except Exception:
                pass

            await asyncio.sleep(0.1)

    # Run command processor in background
    asyncio.create_task(process_commands())

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down login server...")
        print(f"   Final ACL size: {login_handler.get_acl().get_num_clients()} clients")


def main():
    """Main function for running the example."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Run a login authentication server for the mesh network"
    )
    parser.add_argument(
        "--radio-type",
        choices=["waveshare", "uconsole", "meshadv-mini", "kiss-tnc"],
        default="waveshare",
        help="Radio hardware type (default: waveshare)",
    )
    parser.add_argument(
        "--serial-port",
        default="/dev/ttyUSB0",
        help="Serial port for KISS TNC (default: /dev/ttyUSB0)",
    )
    parser.add_argument(
        "--admin-password",
        default="admin123",
        help="Admin password (default: admin123)",
    )
    parser.add_argument(
        "--guest-password",
        default="guest123",
        help="Guest password (default: guest123, empty to disable)",
    )

    args = parser.parse_args()

    print(f"Using {args.radio_type} radio configuration")
    if args.radio_type == "kiss-tnc":
        print(f"Serial port: {args.serial_port}")

    try:
        asyncio.run(
            run_login_server(
                args.radio_type, args.serial_port, args.admin_password, args.guest_password
            )
        )
    except KeyboardInterrupt:
        print("\nExample terminated by user")


if __name__ == "__main__":
    main()
