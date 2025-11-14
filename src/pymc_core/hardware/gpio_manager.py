"""
GPIO Pin Manager for Raspberry Pi
Manages GPIO pins abstraction using gpiozero
"""

import asyncio
import logging
from typing import Callable, Optional

from gpiozero import Button, Device, OutputDevice

# Force gpiozero to use LGPIOFactory - no RPi.GPIO fallback
from gpiozero.pins.lgpio import LGPIOFactory

Device.pin_factory = LGPIOFactory()

logger = logging.getLogger("GPIOPinManager")


class GPIOPinManager:
    """Manages GPIO pins abstraction"""

    def __init__(self):
        self._pins = {}
        self._led_tasks = {}  # Track active LED tasks

    def setup_output_pin(self, pin_number: int, initial_value: bool = False) -> bool:
        """Setup an output pin with initial value"""
        if pin_number == -1:
            return False

        try:
            if pin_number in self._pins:
                self._pins[pin_number].close()

            self._pins[pin_number] = OutputDevice(pin_number, initial_value=initial_value)
            return True
        except Exception as e:
            logger.warning(f"Failed to setup output pin {pin_number}: {e}")
            return False

    def setup_input_pin(
        self,
        pin_number: int,
        pull_up: bool = False,
        callback: Optional[Callable] = None,
    ) -> bool:
        """Setup an input pin with optional interrupt callback"""
        if pin_number == -1:
            return False

        try:
            if pin_number in self._pins:
                self._pins[pin_number].close()

            self._pins[pin_number] = Button(pin_number, pull_up=pull_up)
            if callback:
                self._pins[pin_number].when_activated = callback

            return True
        except Exception as e:
            logger.warning(f"Failed to setup input pin {pin_number}: {e}")
            return False

    def setup_interrupt_pin(
        self,
        pin_number: int,
        pull_up: bool = False,
        callback: Optional[Callable] = None,
    ) -> Optional[Button]:
        """Setup an interrupt pin and return the Button object for direct access"""
        if pin_number == -1:
            return None

        try:
            if pin_number in self._pins:
                self._pins[pin_number].close()

            button = Button(pin_number, pull_up=pull_up)
            if callback:
                button.when_activated = callback

            self._pins[pin_number] = button
            return button
        except Exception as e:
            logger.warning(f"Failed to setup interrupt pin {pin_number}: {e}")
            return None

    def set_pin_high(self, pin_number: int) -> bool:
        """Set output pin to HIGH"""
        if pin_number in self._pins and hasattr(self._pins[pin_number], "on"):
            try:
                self._pins[pin_number].on()
                return True
            except Exception as e:
                logger.warning(f"Failed to set pin {pin_number} HIGH: {e}")
        return False

    def set_pin_low(self, pin_number: int) -> bool:
        """Set output pin to LOW"""
        if pin_number in self._pins and hasattr(self._pins[pin_number], "off"):
            try:
                self._pins[pin_number].off()
                return True
            except Exception as e:
                logger.warning(f"Failed to set pin {pin_number} LOW: {e}")
        return False

    def cleanup_pin(self, pin_number: int) -> None:
        """Clean up a specific pin"""
        if pin_number in self._pins:
            try:
                self._pins[pin_number].close()
                del self._pins[pin_number]
            except Exception as e:
                logger.warning(f"Failed to cleanup pin {pin_number}: {e}")

    def cleanup_all(self) -> None:
        """Clean up all managed pins"""
        # Cancel any running LED tasks
        for task in self._led_tasks.values():
            if not task.done():
                task.cancel()
        self._led_tasks.clear()

        # Clean up pins
        for pin_number in list(self._pins.keys()):
            self.cleanup_pin(pin_number)

    async def _led_blink_task(self, pin_number: int, duration: float = 3.0) -> None:
        """Internal task to blink LED for specified duration"""
        try:
            # Turn LED on
            self.set_pin_high(pin_number)
            logger.debug(f"LED {pin_number} turned ON for {duration}s")

            # Wait for duration
            await asyncio.sleep(duration)

            # Turn LED off
            self.set_pin_low(pin_number)
            logger.debug(f"LED {pin_number} turned OFF")

        except asyncio.CancelledError:
            # Turn off LED if task was cancelled
            self.set_pin_low(pin_number)
            logger.debug(f"LED {pin_number} task cancelled, LED turned OFF")
        except Exception as e:
            logger.warning(f"LED {pin_number} task error: {e}")
        finally:
            # Remove from active tasks
            if pin_number in self._led_tasks:
                del self._led_tasks[pin_number]

    def blink_led(self, pin_number: int, duration: float = 3.0) -> None:
        """
        Blink LED for specified duration (non-blocking)

        Args:
            pin_number: GPIO pin number for LED
            duration: How long to keep LED on (seconds, default: 3.0)
        """
        if pin_number == -1:
            return  # LED disabled

        if pin_number not in self._pins:
            logger.debug(f"LED pin {pin_number} not configured, skipping")
            return

        try:
            # Cancel any existing LED task for this pin
            if pin_number in self._led_tasks and not self._led_tasks[pin_number].done():
                self._led_tasks[pin_number].cancel()

            # Start new LED task
            loop = asyncio.get_running_loop()
            self._led_tasks[pin_number] = loop.create_task(
                self._led_blink_task(pin_number, duration)
            )

        except RuntimeError:
            # No event loop running - just turn on LED (won't auto-turn off)
            logger.debug(f"No event loop, LED pin {pin_number} turned on (manual off required)")
            self.set_pin_high(pin_number)
        except Exception as e:
            logger.warning(f"Failed to start LED task for pin {pin_number}: {e}")
