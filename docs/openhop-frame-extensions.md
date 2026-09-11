# openHop Frame extensions

The companion Frame protocol openHop Core speaks is MeshCore's. This document
covers the handful of frames that are **not** — openHop-specific additions that
a firmware companion does not implement and will reject.

Everything here is confined to the app↔device Frame link. The RF packets these
frames produce are ordinary MeshCore packets: a firmware repeater, or a firmware
companion on the receiving end, cannot tell they were originated through an
extension.

## Design rules

- **Extensions ride on an existing command, never a new command number.**
  Command numbers are MeshCore's to allocate; taking an unused one now would
  collide the moment upstream uses it. The extensions below live in
  `CMD_SEND_CHANNEL_TXT_MSG` (3)'s `txt_type` byte with the high bit set.
  MeshCore's own `TXT_TYPE_*` values are 0–3 and the firmware answers anything
  that is not `TXT_TYPE_PLAIN` with `ERR_CODE_UNSUPPORTED_CMD` *before* it
  touches the radio — so an extension frame sent to a firmware device, or to an
  older openHop Core, fails cleanly rather than transmitting something
  unintended.
- **`FIRMWARE_VER_CODE` does not move for an extension.** That value states
  which MeshCore companion protocol version this device implements. Extensions
  do not change that answer, and inflating it would tell clients that
  unimplemented upstream commands exist.
- **Capability is negotiated explicitly.** A client must receive the exact
  marker below before sending any extension frame.

## Capability probe

Request payload (7 bytes):

| Offset | Size | Value |
| --- | ---: | --- |
| 0 | 1 | `CMD_SEND_CHANNEL_TXT_MSG` = `0x03` |
| 1 | 1 | `OPENHOP_CHANNEL_SCOPE_PROBE` = `0x81` |
| 2 | 5 | reserved; must be present and zero |

The five reserved bytes pad the probe to command 3's minimum parse length, so a
device without these extensions still reads a well-formed command 3 and replies
from its normal unsupported-`txt_type` branch.

Response payload (39 bytes):

| Offset | Size | Value |
| --- | ---: | --- |
| 0 | 1 | `RESP_CODE_OPENHOP_EXTENSION` = `0xF0` |
| 1 | 6 | ASCII `OHREG2` |
| 7 | 32 | this companion's public key |

The public key lets a client bind the answer to one identity: a single openHop
host can front several virtual companions, and capability is a property of the
device the client is actually talking to.

Other replies and what they mean:

| Reply | Meaning |
| --- | --- |
| `RESP_CODE_ERR` / `ERR_CODE_UNSUPPORTED_CMD` | firmware, or openHop Core without these extensions — do not send extension frames |
| `RESP_CODE_ERR` / `ERR_CODE_ILLEGAL_ARG` | the probe itself was malformed (wrong length, or non-zero reserved bytes) |
| `0xF0` with a marker other than `OHREG2` | a different contract revision — do not send extension frames |

`OHREG2` is a whole-contract version, not a per-frame one. Any incompatible
change to a layout on this page bumps the digit; a client must treat an
unrecognised marker as "no extensions", never as "close enough".

> An earlier unmerged draft (`openhop_repeater` PR #417) used `OHREG1` with a
> *normalized* region name on the wire instead of a key. That normalization
> conflated regions that MeshCore keeps distinct — see "Region names are
> case-sensitive" below — so the contract was re-versioned rather than
> redefined in place.

## Scoped channel text send

Sends one channel text message under a caller-supplied transport key, whatever
flood scope the device itself is configured for.

Request payload (23–176 bytes):

| Offset | Size | Value |
| --- | ---: | --- |
| 0 | 1 | `CMD_SEND_CHANNEL_TXT_MSG` = `0x03` |
| 1 | 1 | `OPENHOP_CHANNEL_TXT_SCOPED` = `0x80` |
| 2 | 1 | channel index |
| 3 | 4 | message timestamp, little-endian uint32 |
| 7 | 16 | MeshCore transport key, exact bytes |
| 23 | 1–153 | message text, UTF-8 |

The whole payload is capped at `MAX_FRAME_SIZE` (176), leaving at most 153 text
bytes. Text beyond what a packet holds is truncated by the shared send path on
exactly firmware's terms (see "RF output" below), so a client that stays under
153 bytes is not guaranteed the whole message arrives — the cap is the frame
limit, not the message limit.

Responses:

| Condition | Reply |
| --- | --- |
| sent | `RESP_CODE_OK` |
| unknown channel, or the send failed | `ERR_CODE_NOT_FOUND` |
| malformed payload, bad key, bad text | `ERR_CODE_ILLEGAL_ARG` |

`ERR_CODE_NOT_FOUND` covering both a bad channel index and a transmit failure is
firmware's mapping for command 3, kept here so a client needs one code path for
scoped and plain sends alike.

The frame is rejected with `ERR_CODE_ILLEGAL_ARG` when:

- the payload is shorter than the 23-byte minimum, or longer than 176;
- the text is empty, contains an embedded NUL, or is not valid UTF-8;
- the transport key is not exactly 16 bytes, or is all zeros.

Trailing NUL bytes on the text are accepted and stripped, matching command 3's
C-string convention. An *embedded* NUL is refused rather than silently accepted,
since a client that produced one would itself read the message back truncated.

All-zero keys are refused rather than read as MeshCore's
`TransportKey::isNull()` ("send plain flood"). An explicit per-message override
has no reason to carry the null key, so zeros are much likelier to be an
uninitialised buffer than a deliberate request. To send unscoped, either omit
the override (use plain command 3) or set the device unscoped with
`CMD_SET_FLOOD_SCOPE` mode 1.

### Deriving the key

The key is a raw 16-byte MeshCore `TransportKey`. For a public auto-hashtag
region it is the first 16 bytes of `SHA-256` over the ASCII region name
including the leading `#`:

```python
from openhop_core.protocol.transport_keys import get_auto_key_for

key = get_auto_key_for("#USA")   # 16 bytes
```

Private regions supply their key by whatever means they distribute it; pass
those 16 bytes through unchanged.

### Region names are case-sensitive

`#USA` and `#usa` hash to different keys and are therefore **different
regions**. Nothing in openHop Core case-folds a region name, and clients must
not either — a client that lowercases user input silently moves traffic to a
region the user did not name, and nodes in the intended region never see it.

```python
get_auto_key_for("#USA") != get_auto_key_for("#usa")   # True
```

## RF output

A scoped send produces exactly what MeshCore emits for a scoped group text:

- the `GRP_TXT` payload is built and encrypted normally — same channel hash,
  same MAC, same `"<sender>: "` prefix, same firmware-compatible truncation of
  the text (never the prefix) at the packet's byte limit;
- the route type changes from `FLOOD` (0) to `TRANSPORT_FLOOD` (2);
- transport code slot 0 is `HMAC-SHA256(key, payload_type || payload)`, first
  two bytes read little-endian, with `0x0000` and `0xFFFF` mapped to `0x0001`
  and `0xFFFE` as firmware reserves them;
- transport code slot 1 is 0, firmware's placeholder for the sender's home
  region.

## Relation to `CMD_SET_FLOOD_SCOPE` (54)

Command 54 is MeshCore's and is **sticky**: it sets `send_scope` (or
`send_unscoped`) on the device, and every subsequent flood uses it until the
next command 54. Firmware has no per-message form — `MyMesh::sendFloodScoped`
carries a `// TODO: have per-channel send_scope` where one would go.

The extension is the per-message form. It reads and writes no device state at
all: not `send_scope`, not `send_unscoped`, not the persisted default scope, and
not any dispatcher mirror. Two scoped sends in flight at once, with different
keys, cannot affect each other or any concurrent ordinary send.

This means the two do not interact. A client that wants a *sticky* scope still
uses command 54; a client that wants one message elsewhere uses the extension
and leaves the device's own scope exactly as the user configured it.

## Python API

The same behaviour is available directly, on both `CompanionRadio` and
`CompanionBridge`:

```python
from openhop_core.protocol.transport_keys import get_auto_key_for

await companion.send_channel_message(
    1,
    "hello",
    flood_scope_key=get_auto_key_for("#USA"),
)
```

`flood_scope_key=None` (the default) keeps the node's own resolution:
force-unscoped flag, then transient override, then persisted default, then plain
flood. A key that is not 16 non-zero bytes raises `ValueError` before any packet
is built.
