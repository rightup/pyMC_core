"""Literal conformance vectors for the login reply's ACL bytes.

Pure data with no imports, so downstream projects (openhop_repeater and any
other server built on core) can assert against exactly the same numbers this
package is tested with.

The 13-byte login reply built by firmware ``handleLoginReq`` is::

    timestamp(4) response_code(1) keep_alive(1) admin_code(1) permissions(1)
    random(4) firmware_ver_level(1)

``admin_code`` is byte 6 (the legacy admin flag) and ``permissions`` is byte 7
(the ACL byte modern clients decode). Transcribed from MeshCore firmware at
commit 915ccdb1:

* ``src/helpers/ClientACL.h`` — role numbering and ``isAdmin()``
* ``examples/simple_repeater/MyMesh.cpp`` — ``reply_data[6] = isAdmin() ? 1 : 0``
* ``examples/simple_room_server/MyMesh.cpp`` —
  ``reply_data[6] = isAdmin() ? 1 : (permissions == 0 ? 2 : 0)``

Every value here is a literal on purpose. Asserting against ``PERM_ACL_*``
would follow those constants wherever they drift, which is precisely the
failure these vectors exist to catch (openhop-dev/openhop_repeater#388: the
constants and the code agreed with each other and disagreed with the mesh).
"""

# Role occupying the low two bits of the permissions byte.
ROLE_VALUES = {
    "guest": 0x00,
    "read_only": 0x01,
    "read_write": 0x02,
    "admin": 0x03,
}

ROLE_MASK = 0x03

# Byte 6 states. A room server overloads this byte; everything else sends 0/1.
ADMIN_CODE_NOT_ADMIN = 0x00
ADMIN_CODE_ADMIN = 0x01
ADMIN_CODE_ROOM_GUEST = 0x02

# What a server must put on the wire, by server type and credential.
# (server_type, credential, admin_code, permissions)
OUTBOUND = (
    ("repeater", "admin_password", 0x01, 0x03),
    # A repeater's guest password grants GUEST: base telemetry, no settings.
    ("repeater", "guest_password", 0x00, 0x00),
    ("repeater", "blank_read_only", 0x00, 0x00),
    ("room_server", "admin_password", 0x01, 0x03),
    # A room server's guest password grants READ_WRITE: post and read posts.
    # permissions is non-zero, so byte 6 is 0 rather than the room guest code.
    #
    # REGRESSION SENTINEL. This is the only outbound row that a `permissions &
    # 0x02` admin test gets wrong (2 & 2 is truthy, so it would claim admin);
    # the other four pass on the buggy code. Do not drop it.
    ("room_server", "guest_password", 0x00, 0x02),
)

# What a client must make of bytes it receives, including shapes we never
# emit ourselves but must decode from stock firmware.
# (admin_code, permissions, is_admin, role)
INBOUND = (
    (0x01, 0x03, True, 0x03),
    (0x00, 0x02, False, 0x02),
    (0x00, 0x01, False, 0x01),
    (0x00, 0x00, False, 0x00),
    # REGRESSION SENTINEL. A stock room server's plain guest: byte 6 is 2, and
    # bool(2) is True, so a boolean decode promoted every such guest to admin.
    # This is the only inbound row that discriminates against that decode.
    (0x02, 0x00, False, 0x00),
    # Bits above the role mask are reserved flags and must not change the role.
    (0x01, 0xF3, True, 0x03),
    (0x00, 0xF2, False, 0x02),
)

# Known divergence, deliberately not in OUTBOUND: firmware's room server sends
# admin_code 2 for a blank-password read-only login (permissions == 0), where
# we send 0. Both mean "not admin", so no client is misled about privilege; we
# simply do not reproduce the extra "plain guest" signal on that one path.
