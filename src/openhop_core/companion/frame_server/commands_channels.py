"""Channel command handlers (get/set channel)."""

import logging

from ..constants import (
    CHANNEL_NAME_SIZE,
    ERR_CODE_ILLEGAL_ARG,
    ERR_CODE_NOT_FOUND,
    RESP_CODE_CHANNEL_INFO,
)

logger = logging.getLogger("CompanionFrameServer")


class _ChannelCommandsMixin:
    """Channel _cmd_* handlers of :class:`CompanionFrameServer`."""

    async def _cmd_get_channel(self, data: bytes) -> None:
        get_full_list = len(data) == 0
        channel_idx = data[0] if not get_full_list else 0
        max_channels_val = getattr(getattr(self.bridge, "channels", None), "max_channels", 40)

        def _channel_info_frame(idx: int, ch) -> bytes:
            if ch is None:
                name = b"\x00" * CHANNEL_NAME_SIZE
                secret = b"\x00" * 16
            else:
                name = ch.name.encode("utf-8", errors="replace")[:CHANNEL_NAME_SIZE].ljust(
                    CHANNEL_NAME_SIZE, b"\x00"
                )
                secret = (ch.secret[:16] if ch.secret else b"\x00" * 16).ljust(16, b"\x00")
            return bytes([RESP_CODE_CHANNEL_INFO, idx]) + name + secret

        if get_full_list:
            for idx in range(max_channels_val):
                ch = self.bridge.get_channel(idx)
                frame = _channel_info_frame(idx, ch)
                self._write_frame(frame)
            if max_channels_val == 0:
                # Send at least one frame so client always gets a response per command
                self._write_frame(_channel_info_frame(0, None))
            return

        if channel_idx < 0 or channel_idx >= max_channels_val:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        ch = self.bridge.get_channel(channel_idx)
        frame = _channel_info_frame(channel_idx, ch)
        self._write_frame(frame)

    async def _cmd_set_channel(self, data: bytes) -> None:
        if len(data) < 2 + CHANNEL_NAME_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        channel_idx = data[0]
        name_raw = data[1 : 1 + CHANNEL_NAME_SIZE]
        name = name_raw.split(b"\x00")[0].decode("utf-8", errors="replace").strip()
        if len(data) >= 97:
            try:
                secret = bytes.fromhex(data[33:97].decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                self._write_err(ERR_CODE_ILLEGAL_ARG)
                return
        elif len(data) >= 65:
            secret = data[33:65]
        elif len(data) >= 49:
            secret = data[33:49]
        else:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        ok = self.bridge.set_channel(channel_idx, name, secret)
        if ok:
            try:
                await self._save_channels()
            except Exception as e:
                logger.warning("Save channels after set failed: %s", e)
        self._write_ok() if ok else self._write_err(ERR_CODE_NOT_FOUND)
