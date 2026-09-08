import threading
from unittest.mock import MagicMock


def _make_polling_manager():
    from openhop_core.hardware.gpio_manager import GPIOPinManager

    gm = object.__new__(GPIOPinManager)
    gm._pins = {}
    gm._input_callbacks = {}
    return gm


def _run_polling(gm, pin, reads, interval=0.001):
    stop_event = threading.Event()
    read_idx = [0]

    def read_pin():
        i = read_idx[0]
        read_idx[0] += 1
        if i >= len(reads):
            stop_event.set()
            return False
        return reads[i]

    mock_pin = MagicMock()
    mock_pin.read.side_effect = read_pin
    gm._pins[pin] = mock_pin

    callbacks = []
    gm._input_callbacks[pin] = lambda: callbacks.append(1)

    thread = threading.Thread(
        target=gm._monitor_polling,
        args=(pin, stop_event, interval),
        daemon=True,
    )
    thread.start()
    thread.join(timeout=2.0)
    assert not thread.is_alive(), "Polling thread did not terminate within 2s"
    return callbacks


def test_stuck_high_recovers_with_second_callback():
    """LOW -> HIGH -> HIGH -> HIGH should fire twice with stuck-HIGH recovery."""
    gm = _make_polling_manager()
    callbacks = _run_polling(gm, pin=16, reads=[False, True, True, True])

    assert len(callbacks) == 2, (
        f"Expected 2 callbacks (initial edge + recovery), got {len(callbacks)}."
    )
