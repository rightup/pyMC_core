"""
Lightweight mesh event constants for the mesh library.
These are the core events that mesh handlers can publish.
"""


class MeshEvents:
    """Standard mesh event types for the mesh library."""

    # Contact events
    NEW_CONTACT = "mesh.contact.new"
    CONTACT_UPDATED = "mesh.contact.updated"

    # Message events
    NEW_MESSAGE = "mesh.message.new"
    MESSAGE_READ = "mesh.message.read"
    UNREAD_COUNT_CHANGED = "mesh.message.unread_count_changed"

    # Channel events
    NEW_CHANNEL_MESSAGE = "mesh.channel.message.new"
    CHANNEL_UPDATED = "mesh.channel.updated"

    # Network events
    NODE_DISCOVERED = "mesh.network.node_discovered"
    SIGNAL_STRENGTH_UPDATED = "mesh.network.signal_updated"

    # System events
    NODE_STARTED = "mesh.system.node_started"
    NODE_STOPPED = "mesh.system.node_stopped"
    TELEMETRY_UPDATED = "mesh.system.telemetry_updated"
