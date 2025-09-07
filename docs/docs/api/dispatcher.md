# Dispatcher API Reference

This section documents the Dispatcher class and related functionality in pyMC_Core.

## Dispatcher

::: pymc_core.node.dispatcher.Dispatcher
    handler: python
    options:
      show_root_heading: true
      show_source: false
      show_symbol_type_heading: true

## Dispatcher Components

### Packet Routing

The Dispatcher handles routing of packets to appropriate handlers based on packet type and content.

### Handler Registration

```python
# Register a handler for specific packet types
dispatcher.register_handler(PacketType.DATA, data_handler)
dispatcher.register_handler(PacketType.ACK, ack_handler)
```

### Packet Transmission

```python
# Send packets through the dispatcher
await dispatcher.send_packet(packet)
```

## Key Methods

- `register_handler(packet_type, handler)` - Register a handler for a packet type
- `unregister_handler(packet_type, handler)` - Remove a handler registration
- `send_packet(packet)` - Send a packet through the dispatcher
- `handle_packet(packet)` - Process an incoming packet
- `get_registered_handlers()` - Get list of registered handlers

## Handler Interface

All packet handlers should implement the following interface:

```python
class PacketHandler:
    async def handle_packet(self, packet: Packet) -> None:
        """Handle an incoming packet."""
        pass
```

## Packet Flow

1. **Incoming Packet** → Dispatcher.receive_packet()
2. **Handler Lookup** → Find registered handler for packet type
3. **Handler Execution** → Call handler.handle_packet(packet)
4. **Response Handling** → Handle any response packets generated

## Error Handling

The Dispatcher includes built-in error handling for:
- Invalid packet types
- Handler execution errors
- Packet validation failures
- Transmission timeouts

## Thread Safety

The Dispatcher is designed to be thread-safe for concurrent packet handling and registration operations.
