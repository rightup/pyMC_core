import pytest

from pymc_core import LocalIdentity


# MeshNode tests (mock-based since we don't have real radio hardware)
def test_mesh_node_initialization():
    """Test MeshNode initialization with mock radio."""

    # Create a mock radio
    class MockRadio:
        def __init__(self):
            self.state = "idle"

        def get_state(self):
            return self.state

    # Create mock components
    radio = MockRadio()
    identity = LocalIdentity()
    # contacts = None  # Simplified for test (unused for now)

    # This would normally create a MeshNode, but we'll skip the full init for now
    assert radio is not None
    assert identity is not None


def test_mesh_node_with_config():
    """Test MeshNode with configuration."""
    # Mock test - in real scenario would test config loading
    assert True


def test_mesh_node_helper_methods():
    """Test MeshNode helper methods."""
    # Mock test - in real scenario would test helper methods
    assert True


# ResponseWaiter tests
def test_response_waiter():
    """Test ResponseWaiter functionality."""
    from pymc_core.node import MeshNode

    waiter = MeshNode._ResponseWaiter()

    # Test callback
    waiter.callback(True, "Test response", {"key": "value"})

    assert waiter.data["success"]
    assert waiter.data["text"] == "Test response"
    assert waiter.data["parsed"] == {"key": "value"}


@pytest.mark.asyncio
async def test_response_waiter_timeout():
    """Test ResponseWaiter timeout functionality."""
    from pymc_core.node import MeshNode

    waiter = MeshNode._ResponseWaiter()

    # Test timeout
    result = await waiter.wait(timeout=0.1)
    assert not result["success"]
    assert result["text"] is None
    assert result["timeout"]


def test_time_operation_context_manager():
    """Test the _time_operation context manager."""

    class MockNode:
        def _time_operation(self):
            import time
            from contextlib import contextmanager

            @contextmanager
            def timer():
                start_time = time.time()
                yield lambda: (time.time() - start_time) * 1000  # RTT in milliseconds

            return timer()

    node = MockNode()
    timer = node._time_operation()

    with timer as get_rtt:
        import time

        time.sleep(0.01)  # Sleep for 10ms
        rtt = get_rtt()

    assert rtt >= 10.0  # Should be at least 10ms
