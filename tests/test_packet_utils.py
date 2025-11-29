import struct

import pytest

from pymc_core.protocol.constants import (
    ADVERT_FLAG_HAS_FEATURE1,
    ADVERT_FLAG_HAS_FEATURE2,
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    ADVERT_FLAG_IS_SENSOR,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    PUB_KEY_SIZE,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
)
from pymc_core.protocol.packet_utils import (
    PacketDataUtils,
    PacketHashingUtils,
    PacketTimingUtils,
    PacketValidationUtils,
)
from pymc_core.protocol.utils import decode_appdata, parse_advert_payload


class TestPacketValidationUtils:
    def test_validate_routing_path_valid_inputs(self):
        """Test routing path validation with valid inputs."""
        # Valid integer path
        path = [1, 2, 3, 255]
        result = PacketValidationUtils.validate_routing_path(path)
        assert result == [1, 2, 3, 255]

        # Valid hex string path
        path = ["01", "FF", "A5"]
        result = PacketValidationUtils.validate_routing_path(path)
        assert result == [1, 255, 165]

        # Mixed types
        path = [1, "FF", 255, "00"]
        result = PacketValidationUtils.validate_routing_path(path)
        assert result == [1, 255, 255, 0]

        # Float conversion
        path = [1.0, 2.5, 255.9]
        result = PacketValidationUtils.validate_routing_path(path)
        assert result == [1, 2, 255]

    def test_validate_routing_path_invalid_inputs(self):
        """Test routing path validation with invalid inputs."""
        # Not a list
        with pytest.raises(ValueError, match="routing_path must be a list"):
            PacketValidationUtils.validate_routing_path("not_a_list")

        # Path too long
        long_path = [0] * (MAX_PATH_SIZE + 1)
        with pytest.raises(
            ValueError,
            match=f"Path length {len(long_path)} exceeds maximum {MAX_PATH_SIZE}",
        ):
            PacketValidationUtils.validate_routing_path(long_path)

        # Invalid hex string - too short
        with pytest.raises(ValueError, match="hex string 'F' too short"):
            PacketValidationUtils.validate_routing_path(["F"])

        # Invalid hex characters
        with pytest.raises(ValueError, match="contains invalid hex characters"):
            PacketValidationUtils.validate_routing_path(["GG"])

        # Value out of range - negative
        with pytest.raises(ValueError, match="value -1 out of range"):
            PacketValidationUtils.validate_routing_path([-1])

        # Value out of range - too high
        with pytest.raises(ValueError, match="value 256 out of range"):
            PacketValidationUtils.validate_routing_path([256])

        # Invalid type
        with pytest.raises(ValueError, match="invalid type .* for value"):
            PacketValidationUtils.validate_routing_path([None])

    def test_validate_packet_bounds(self):
        """Test packet bounds validation."""
        # Valid bounds
        PacketValidationUtils.validate_packet_bounds(0, 4, 10, "test error")
        PacketValidationUtils.validate_packet_bounds(6, 4, 10, "test error")

        # Invalid bounds - not enough data
        with pytest.raises(ValueError, match="test error"):
            PacketValidationUtils.validate_packet_bounds(7, 4, 10, "test error")

        # Edge case - exact boundary
        PacketValidationUtils.validate_packet_bounds(6, 4, 10, "test error")

    def test_validate_buffer_lengths(self):
        """Test buffer length validation."""
        # Valid lengths
        PacketValidationUtils.validate_buffer_lengths(5, 5, 10, 10)

        # Invalid path length
        with pytest.raises(ValueError, match="path_len mismatch: expected 5, got 6"):
            PacketValidationUtils.validate_buffer_lengths(5, 6, 10, 10)

        # Invalid payload length
        with pytest.raises(ValueError, match="payload_len mismatch: expected 10, got 15"):
            PacketValidationUtils.validate_buffer_lengths(5, 5, 10, 15)

    def test_validate_payload_size(self):
        """Test payload size validation."""
        # Valid sizes
        PacketValidationUtils.validate_payload_size(100)
        PacketValidationUtils.validate_payload_size(MAX_PACKET_PAYLOAD)

        # Invalid size - too large
        with pytest.raises(
            ValueError,
            match=f"payload too large: {MAX_PACKET_PAYLOAD + 1} > {MAX_PACKET_PAYLOAD}",
        ):
            PacketValidationUtils.validate_payload_size(MAX_PACKET_PAYLOAD + 1)


class TestPacketDataUtils:
    def test_pack_timestamp_data(self):
        """Test timestamp + data packing."""
        timestamp = 1234567890
        data1 = b"hello"
        data2 = 42
        data3 = "world"

        result = PacketDataUtils.pack_timestamp_data(timestamp, data1, data2, data3)

        # Should start with timestamp as little-endian 4 bytes
        expected_timestamp = struct.pack("<I", timestamp)
        assert result.startswith(expected_timestamp)

        # Should contain the data parts
        assert data1 in result
        assert bytes([data2]) in result  # Integer packed as single byte
        assert data3.encode() in result

    def test_pack_timestamp_data_edge_cases(self):
        """Test edge cases for timestamp data packing."""
        # No additional data
        result = PacketDataUtils.pack_timestamp_data(1234567890)
        expected_timestamp = struct.pack("<I", 1234567890)
        assert result == expected_timestamp

        # Large timestamp
        large_timestamp = 2**32 - 1  # Max uint32
        result = PacketDataUtils.pack_timestamp_data(large_timestamp)
        expected = struct.pack("<I", large_timestamp)
        assert result == expected

        # Zero timestamp
        result = PacketDataUtils.pack_timestamp_data(0)
        expected = struct.pack("<I", 0)
        assert result == expected


class TestPacketHashingUtils:
    def test_hash_string_returns_full_uppercase_hex(self):
        payload_type = 0x05
        path_len = 0
        payload = bytes.fromhex("D9BA8E4EA9444822AC56B4D52AC3C0044C6AE402997BB9805CCB331EC3378DCE339F2D")

        expected_hex = "887B9BE6056D0B0517AF3A04AC2478EDFC2AB731936DEA525041500E7ADE74D3"

        result = PacketHashingUtils.calculate_packet_hash_string(
            payload_type=payload_type,
            path_len=path_len,
            payload=payload,
            length=None,
        )

        assert result == expected_hex
        assert result.isupper()

    def test_hash_string_truncates_to_requested_length(self):
        payload_type = 0x05
        path_len = 1
        payload = bytes.fromhex("D9BA8E4EA9444822AC56B4D52AC3C0044C6AE402997BB9805CCB331EC3378DCE339F2D")

        expected_hex = "887B9BE6056D0B05"

        truncated = PacketHashingUtils.calculate_packet_hash_string(
            payload_type=payload_type,
            path_len=path_len,
            payload=payload,
            length=16,
        )

        assert truncated == expected_hex[:16]
        assert len(truncated) == 16
        assert truncated.isupper()


class TestAppdataDecoding:
    def test_decode_appdata_parses_optional_fields(self):
        flags = (
            ADVERT_FLAG_HAS_LOCATION
            | ADVERT_FLAG_HAS_FEATURE1
            | ADVERT_FLAG_HAS_FEATURE2
            | ADVERT_FLAG_HAS_NAME
        )
        lat_raw, lon_raw = 12_345_678, -98_765_432
        feature_1 = 0x1234
        feature_2 = 0xABCD
        name = "MeshNode"
        appdata = bytearray([flags])
        appdata.extend(struct.pack("<ii", lat_raw, lon_raw))
        appdata.extend(struct.pack("<H", feature_1))
        appdata.extend(struct.pack("<H", feature_2))
        appdata.extend(name.encode("utf-8") + b"\x00")

        decoded = decode_appdata(bytes(appdata))

        assert decoded["flags"] == flags
        assert decoded["latitude"] == pytest.approx(lat_raw / 1_000_000.0)
        assert decoded["longitude"] == pytest.approx(lon_raw / 1_000_000.0)
        assert decoded["feature_1"] == feature_1
        assert decoded["feature_2"] == feature_2
        assert decoded["node_name"] == name

    def test_decode_appdata_raises_when_flagged_field_is_missing(self):
        flags = ADVERT_FLAG_HAS_FEATURE1
        with pytest.raises(ValueError, match="feature_1"):
            decode_appdata(bytes([flags]))

    def test_decode_appdata_preserves_sensor_only_prefix_payload(self):
        flags = ADVERT_FLAG_IS_SENSOR
        decoded = decode_appdata(bytes([flags]))
        assert decoded == {"flags": flags}

    def test_decode_appdata_records_invalid_utf8_names(self):
        flags = ADVERT_FLAG_HAS_NAME
        invalid_name = bytes([0xFF, 0xFE])
        decoded = decode_appdata(bytes([flags]) + invalid_name)
        assert "node_name" not in decoded
        assert decoded["raw_name_bytes"] == invalid_name.hex()
        assert decoded["name_decode_error"] is True


def test_parse_advert_payload_allows_flag_only_appdata():
    pubkey = bytes(range(PUB_KEY_SIZE))
    timestamp = (123456789).to_bytes(TIMESTAMP_SIZE, "little")
    signature = bytes(range(PUB_KEY_SIZE, PUB_KEY_SIZE + SIGNATURE_SIZE))
    appdata = bytes([ADVERT_FLAG_IS_SENSOR])

    payload = pubkey + timestamp + signature + appdata
    parsed = parse_advert_payload(payload)

    assert parsed["pubkey"] == pubkey.hex()
    assert parsed["appdata"] == appdata


class TestPacketTimingUtils:
    def test_estimate_airtime_matches_meshcore_formula_defaults(self):
        airtime = PacketTimingUtils.estimate_airtime_ms(64)
        assert airtime == pytest.approx(349.184, rel=1e-3)

    def test_estimate_airtime_respects_ldro_and_override(self):
        config = {
            "spreading_factor": 12,
            "bandwidth": 125_000,
            "coding_rate": 5,
            "preamble_length": 8,
        }
        airtime = PacketTimingUtils.estimate_airtime_ms(16, config)
        assert airtime == pytest.approx(1318.912, rel=1e-3)

        measured = PacketTimingUtils.estimate_airtime_ms(16, {"measured_airtime_ms": 42.0})
        assert measured == 42.0

    def test_calc_rx_delay_matches_dispatcher_formula(self):
        airtime = 350.0
        delay = PacketTimingUtils.calc_rx_delay_ms(score=0.5, packet_airtime_ms=airtime)
        assert delay == 434

        zero_delay = PacketTimingUtils.calc_rx_delay_ms(score=1.5, packet_airtime_ms=airtime)
        assert zero_delay == 0

    def test_airtime_budget_and_cad_constants(self):
        airtime = 200.0
        assert PacketTimingUtils.calc_airtime_budget_delay_ms(airtime) == pytest.approx(400.0)
        assert PacketTimingUtils.calc_airtime_budget_delay_ms(airtime, budget_factor=1.5) == pytest.approx(300.0)
        assert PacketTimingUtils.get_cad_fail_retry_delay_ms() == 200
        assert PacketTimingUtils.get_cad_fail_max_duration_ms() == 4000
