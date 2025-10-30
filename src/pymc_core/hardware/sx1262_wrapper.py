"""
SX1262 LoRa Radio Driver for Raspberry Pi
Implements the LoRaRadio interface using the SX126x library
"""

import asyncio
import logging
import time
from typing import Callable, Optional

from gpiozero import Button, Device, OutputDevice

# Force gpiozero to use LGPIOFactory - no RPi.GPIO fallback
from gpiozero.pins.lgpio import LGPIOFactory

from .base import LoRaRadio
from .lora.LoRaRF.SX126x import SX126x

Device.pin_factory = LGPIOFactory()

logger = logging.getLogger("SX1262_wrapper")


class GPIOPinManager:
    """Manages GPIO pins abstraction"""

    def __init__(self):
        self._pins = {}

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
        for pin_number in list(self._pins.keys()):
            self.cleanup_pin(pin_number)


class SX1262Radio(LoRaRadio):
    """SX1262 LoRa Radio implementation for Raspberry Pi"""

    # Class variable to track the active instance (singleton-like behavior)
    _active_instance = None

    # Common timing constants to avoid magic numbers
    RADIO_TIMING_DELAY = 0.01  # 10ms delay for radio operations

    def __init__(
        self,
        bus_id: int = 0,
        cs_id: int = 0,
        cs_pin: int = -1,
        reset_pin: int = 18,
        busy_pin: int = 20,
        irq_pin: int = 16,
        txen_pin: int = 6,
        rxen_pin: int = -1,
        frequency: int = 868000000,
        tx_power: int = 22,
        spreading_factor: int = 7,
        bandwidth: int = 125000,
        coding_rate: int = 5,
        preamble_length: int = 12,
        sync_word: int = 0x3444,
        is_waveshare: bool = False,
    ):
        """
        Initialize SX1262 radio

        Args:
            bus_id: SPI bus ID (default: 0)
            cs_id: SPI chip select ID (default: 0)
            cs_pin: Manual CS GPIO pin (-1 = use hardware CS, e.g. 21 for Waveshare HAT)
            reset_pin: GPIO pin for reset (default: 18)
            busy_pin: GPIO pin for busy signal (default: 20)
            irq_pin: GPIO pin for interrupt (default: 16)
            txen_pin: GPIO pin for TX enable (default: 6)
            rxen_pin: GPIO pin for RX enable (default: -1 if not used)
            frequency: Operating frequency in Hz (default: 868MHz)
            tx_power: TX power in dBm (default: 22)
            spreading_factor: LoRa spreading factor (default: 7)
            bandwidth: Bandwidth in Hz (default: 125kHz)
            coding_rate: Coding rate (default: 5 for 4/5)
            preamble_length: Preamble length (default: 12)
            sync_word: Sync word (default: 0x3444 for public network)
            is_waveshare: Use alternate initialization needed for Waveshare HAT
        """
        # Check if there's already an active instance and clean it up
        if SX1262Radio._active_instance is not None:
            logger.warning("Another SX1262Radio instance is already active - cleaning it up first")
            try:
                SX1262Radio._active_instance.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up previous instance: {e}")
            SX1262Radio._active_instance = None

        self.bus_id = bus_id
        self.cs_id = cs_id
        self.cs_pin = cs_pin
        self.reset_pin = reset_pin
        self.busy_pin = busy_pin
        self.irq_pin_number = irq_pin  # Store pin number
        self.txen_pin = txen_pin
        self.rxen_pin = rxen_pin

        # Radio configuration
        self.frequency = frequency
        self.tx_power = tx_power
        self.spreading_factor = spreading_factor
        self.bandwidth = bandwidth
        self.coding_rate = coding_rate
        self.preamble_length = preamble_length
        self.sync_word = sync_word
        self.is_waveshare = is_waveshare

        # State variables
        self.lora: Optional[SX126x] = None
        self.last_rssi: int = -99
        self.last_snr: float = 0.0
        self._initialized = False
        self._rx_lock = asyncio.Lock()
        self._tx_lock = asyncio.Lock()
        
        # Noise floor monitoring for debugging
        self._last_noise_floor: Optional[float] = None
        self._noise_floor_history: list = []  # Keep last 10 readings

        # GPIO management
        self._gpio_manager = GPIOPinManager()
        self._interrupt_setup = False
        self._txen_pin_setup = False  # Track if TXEN pin is set up

        self._tx_done_event = asyncio.Event()
        self._rx_done_event = asyncio.Event()
        self._cad_event = asyncio.Event()

        logger.info(
            f"SX1262Radio configured: freq={frequency/1e6:.1f}MHz, "
            f"power={tx_power}dBm, sf={spreading_factor}, "
            f"bw={bandwidth/1000:.1f}kHz, pre={preamble_length}"
        )
        # Register this instance as the active radio for IRQ callback access
        SX1262Radio._active_instance = self

        # RX callback for received packets
        self.rx_callback = None

    def _get_rx_irq_mask(self) -> int:
        """Get the standard RX interrupt mask"""
        return (
            self.lora.IRQ_RX_DONE
            | self.lora.IRQ_CRC_ERR
            | self.lora.IRQ_TIMEOUT
            | self.lora.IRQ_PREAMBLE_DETECTED
            | self.lora.IRQ_SYNC_WORD_VALID
            | self.lora.IRQ_HEADER_VALID
            | self.lora.IRQ_HEADER_ERR
        )

    def _get_tx_irq_mask(self) -> int:
        """Get the standard TX interrupt mask"""
        return self.lora.IRQ_TX_DONE | self.lora.IRQ_TIMEOUT

    def _safe_radio_operation(
        self, operation_name: str, operation_func, success_msg: str = None
    ) -> bool:
        """Helper method for safe radio operations with consistent error handling (DRY)"""
        if not self._initialized or self.lora is None:
            return False

        try:
            operation_func()
            if success_msg:
                logger.debug(success_msg)
            return True
        except Exception as e:
            logger.error(f"Failed to {operation_name}: {e}")
            return False

    def _basic_radio_setup(self, use_busy_check: bool = False) -> bool:
        """Common radio setup: reset, standby, and LoRa packet type"""
        self.lora.reset()
        self.lora.setStandby(self.lora.STANDBY_RC)

        # Check if standby mode was set correctly (different methods for different boards)
        if use_busy_check:
            if self.lora.busyCheck():
                logger.error("Something wrong, can't set to standby mode")
                return False
        else:
            if self.lora.getMode() != self.lora.STATUS_MODE_STDBY_RC:
                logger.error("Something wrong, can't set to standby mode")
                return False

        self.lora.setPacketType(self.lora.LORA_MODEM)
        return True

    def _handle_interrupt(self):
        """Simple instance method interrupt handler"""
        logger.debug("Interrupt handler called!")
        try:
            if not self._initialized or not self.lora:
                logger.warning("Interrupt called but radio not initialized")
                return

            # Read IRQ status and handle
            irqStat = self.lora.getIrqStatus()
            logger.debug(f"Interrupt IRQ status: 0x{irqStat:04X}")

            # Log specific interrupt types for debugging
            if irqStat & self.lora.IRQ_TX_DONE:
                logger.debug("[TX] TX_DONE interrupt (0x{:04X})".format(self.lora.IRQ_TX_DONE))
                self._tx_done_event.set()

            # Check for CAD interrupts
            cad_detected_flag = getattr(self.lora, 'IRQ_CAD_DETECTED', 0x4000)
            cad_done_flag = getattr(self.lora, 'IRQ_CAD_DONE', 0x8000)
            if irqStat & (cad_detected_flag | cad_done_flag):
                logger.debug(f"[CAD] CAD interrupt detected (0x{irqStat:04X})")
                if hasattr(self, '_cad_event'):
                    self._cad_event.set()

            # Check each RX interrupt type separately for better debugging
            rx_interrupts = self._get_rx_irq_mask()
            if irqStat & self.lora.IRQ_RX_DONE:
                logger.debug("[RX] RX_DONE interrupt (0x{:04X})".format(self.lora.IRQ_RX_DONE))
                self._rx_done_event.set()
            elif irqStat & self.lora.IRQ_CRC_ERR:
                logger.debug("[RX] CRC_ERR interrupt (0x{:04X})".format(self.lora.IRQ_CRC_ERR))
                self._rx_done_event.set()
            elif irqStat & self.lora.IRQ_TIMEOUT:
                logger.debug("[RX] TIMEOUT interrupt (0x{:04X})".format(self.lora.IRQ_TIMEOUT))
                self._rx_done_event.set()
            elif irqStat & rx_interrupts:
                logger.debug(f"[RX] Other RX interrupt detected: 0x{irqStat & rx_interrupts:04X}")
                self._rx_done_event.set()

        except Exception as e:
            logger.error(f"IRQ handler error: {e}")
            # Fallback: set both events if we can't read status
            self._tx_done_event.set()
            self._rx_done_event.set()

    def set_rx_callback(self, callback):
        """Set a callback to be called with each received packet (bytes)."""
        self.rx_callback = callback

        # If we have interrupts but no background task yet, start it now
        if (
            self._interrupt_setup
            and self._initialized
            and (
                not hasattr(self, "_rx_irq_task")
                or self._rx_irq_task is None
                or self._rx_irq_task.done()
            )
        ):
            try:
                loop = asyncio.get_running_loop()
                self._rx_irq_task = loop.create_task(self._rx_irq_background_task())
            except RuntimeError:
                pass
            except Exception as e:
                logger.warning(f"Failed to start delayed RX IRQ background handler: {e}")

    async def _rx_irq_background_task(self):
        """Background task: waits for RX_DONE IRQ and processes received packets automatically."""
        logger.debug("[RX] Starting RX IRQ background task")
        rx_check_count = 0
        last_preamble_time = 0
        preamble_timeout = 5.0  # 5 seconds timeout for incomplete preamble detection
        preamble_detect_count = 0  # Counter for preamble detections
        while self._initialized:
            if self._interrupt_setup:
                # Wait for RX_DONE event
                try:
                    await asyncio.wait_for(self._rx_done_event.wait(), timeout=0.01)
                    self._rx_done_event.clear()
                    logger.debug("[RX] RX_DONE event triggered!")

                    try:
                        # Read and process the received packet
                        irqStat = self.lora.getIrqStatus()
                        logger.debug(f"[RX] IRQ Status: 0x{irqStat:04X}")

                        # Clear RX-related interrupt flags only
                        rx_flags = self._get_rx_irq_mask()
                        flags_to_clear = irqStat & rx_flags
                        if flags_to_clear:
                            self.lora.clearIrqStatus(flags_to_clear)

                        if irqStat & self.lora.IRQ_RX_DONE:
                            last_preamble_time = 0  # Reset preamble timer on successful RX
                            (
                                payloadLengthRx,
                                rxStartBufferPointer,
                            ) = self.lora.getRxBufferStatus()
                            rssiPkt, snrPkt, signalRssiPkt = self.lora.getPacketStatus()
                            self.last_rssi = int(rssiPkt / -2)
                            self.last_snr = snrPkt / 4

                            logger.debug(
                                f"[RX] Packet received: length={payloadLengthRx}, "
                                f"RSSI={self.last_rssi}dBm, SNR={self.last_snr}dB"
                            )

                            if payloadLengthRx > 0:
                                buffer = self.lora.readBuffer(rxStartBufferPointer, payloadLengthRx)
                                packet_data = bytes(buffer)
                                logger.debug(
                                    f"[RX] Packet data: {packet_data.hex()[:32]}... "
                                    f"({len(packet_data)} bytes)"
                                )

                                # Call user RX callback if set
                                if self.rx_callback:
                                    try:
                                        logger.debug("[RX] Calling dispatcher callback")
                                        self.rx_callback(packet_data)
                                    except Exception as cb_exc:
                                        logger.error(f"RX callback error: {cb_exc}")
                                else:
                                    logger.warning("[RX] No RX callback registered!")
                            else:
                                logger.warning("[RX] Empty packet received")
                        elif irqStat & self.lora.IRQ_CRC_ERR:
                            logger.warning("[RX] CRC error detected")
                            last_preamble_time = 0  # Reset preamble timer on CRC error
                        elif irqStat & self.lora.IRQ_TIMEOUT:
                            last_preamble_time = 0  # Reset preamble timer on timeout
                        elif irqStat & self.lora.IRQ_PREAMBLE_DETECTED:
                            preamble_detect_count += 1
                            # Log detailed preamble detection info
                            try:
                                raw_rssi = self.lora.getRssiInst()
                                # Calculate preamble RSSI for potential future use
                                # preamble_rssi_dbm = (
                                #     -(float(raw_rssi) / 2)
                                #     if raw_rssi is not None
                                #     else "N/A"
                                # )
                                if preamble_detect_count % 10 == 0:
                                    logger.warning(
                                        f"[IRQ RX] {preamble_detect_count} preamble detections "
                                        f"without valid packets - possible RF noise interference"
                                    )
                            except Exception:
                                pass
                            last_preamble_time = time.time()  # Record when preamble was detected
                        elif irqStat & self.lora.IRQ_SYNC_WORD_VALID:
                            pass  # Sync word valid - receiving packet data...
                        elif irqStat & self.lora.IRQ_HEADER_VALID:
                            pass  # Header valid - packet header received, payload coming...
                        elif irqStat & self.lora.IRQ_HEADER_ERR:
                            pass  # Header error - corrupted header, packet dropped
                        else:
                            pass  # Other RX interrupt

                        # For preamble detection, don't put radio back to RX mode immediately
                        # Let the packet reception complete naturally
                        if not (irqStat & self.lora.IRQ_PREAMBLE_DETECTED):
                            # Always ensure radio stays in RX continuous mode after
                            # any RX interrupt (except preamble)
                            try:
                                self.lora.setRx(self.lora.RX_CONTINUOUS)
                            except Exception:
                                pass
                        else:
                            # Skipping RX mode reset during preamble detection -
                            # letting packet complete
                            pass
                    except Exception as e:
                        logger.error(f"[IRQ RX] Error processing received packet: {e}")

                except asyncio.TimeoutError:
                    # No RX event within timeout - normal operation
                    rx_check_count += 1

                    # Check for stalled preamble detection (preamble detected but no follow-up)
                    current_time = time.time()
                    if (
                        last_preamble_time > 0
                        and (current_time - last_preamble_time) > preamble_timeout
                    ):
                        logger.warning(
                            f"[RX Task] Preamble timeout detected - {preamble_timeout}s "
                            f"elapsed since preamble, resetting radio. This may trigger AGC corruption!"
                        )
                        
                        # Capture noise floor BEFORE preamble timeout reset
                        try:
                            pre_reset_noise = self.get_noise_floor()
                            logger.info(f"[PREAMBLE RESET] Noise floor BEFORE reset: {pre_reset_noise:.1f}dBm")
                        except Exception as e:
                            logger.warning(f"[PREAMBLE RESET] Failed to read pre-reset noise floor: {e}")
                        
                        try:
                            # Force radio back to RX mode to clear any stuck state
                            self.lora.setRx(self.lora.RX_CONTINUOUS)
                            # Clear any pending interrupt flags
                            irqStat = self.lora.getIrqStatus()
                            if irqStat != 0:
                                self.lora.clearIrqStatus(irqStat)
                        except Exception as e:
                            logger.error(
                                f"[RX Task] Failed to reset radio after preamble timeout: {e}"
                            )
                        
                        # Capture noise floor AFTER preamble timeout reset
                        try:
                            await asyncio.sleep(0.1)  # Let radio settle
                            post_reset_noise = self.get_noise_floor()
                            logger.info(f"[PREAMBLE RESET] Noise floor AFTER reset: {post_reset_noise:.1f}dBm")
                            
                            if pre_reset_noise and post_reset_noise:
                                change = abs(post_reset_noise - pre_reset_noise)
                                if change > 5.0:
                                    logger.error(f"[PREAMBLE RESET] CORRUPTION DETECTED! Preamble reset caused {change:.1f}dBm change")
                                    # Collect diagnostics immediately
                                    diag_data = self._collect_radio_diagnostics()
                                    logger.error(f"[PREAMBLE RESET] Post-reset diagnostics: {diag_data}")
                        except Exception as e:
                            logger.warning(f"[PREAMBLE RESET] Failed to read post-reset noise floor: {e}")
                        
                        last_preamble_time = 0  # Reset preamble timer

                    # Log every 500 checks (roughly every 5 seconds) to show RX task is alive
                    # Also check every 100 checks (1 second) for noise floor corruption
                    if rx_check_count % 100 == 0 or rx_check_count % 500 == 0:
                        # Use our safe get_noise_floor method instead of direct getRssiInst
                        try:
                            noise_floor = self.get_noise_floor()
                            if noise_floor is not None:
                                # Debug noise floor changes
                                if self._last_noise_floor is not None:
                                    change = abs(noise_floor - self._last_noise_floor)
                                    if change > 5.0:  # Log significant changes (>5dBm)
                                        logger.warning(f"NOISE FLOOR CHANGE DETECTED: {self._last_noise_floor:.1f} -> {noise_floor:.1f} dBm (change: {change:.1f} dBm)")
                                        
                                        # Collect comprehensive radio diagnostics
                                        diag_data = self._collect_radio_diagnostics()
                                        logger.info(f"Radio diagnostics at corruption: {diag_data}")
                                        
                                        # Check if AGC registers are corrupted (all showing 0x00)
                                        agc_corrupted = (
                                            diag_data.get("rx_gain_reg") == "0x00" and
                                            diag_data.get("agc_ctrl_reg") == "0x00" and 
                                            diag_data.get("agc_config_reg") == "0x00"
                                        )
                                        
                                        if agc_corrupted:
                                            logger.error("AGC REGISTER CORRUPTION DETECTED! All AGC registers showing 0x00 - attempting immediate restoration")
                                            # Attempt immediate AGC restoration
                                            try:
                                                success = await self._restore_agc_system()
                                                if success:
                                                    logger.info("AGC system restoration completed successfully")
                                                    # Verify restoration worked
                                                    await asyncio.sleep(0.1)
                                                    new_noise_floor = self.get_noise_floor()
                                                    if new_noise_floor and new_noise_floor < -100.0:
                                                        logger.info(f"AGC restoration verified - noise floor now: {new_noise_floor:.1f}dBm")
                                                    else:
                                                        logger.warning(f"AGC restoration may have failed - noise floor still: {new_noise_floor:.1f}dBm")
                                                else:
                                                    logger.error("AGC system restoration failed")
                                            except Exception as e:
                                                logger.error(f"AGC restoration attempt failed: {e}")
                                        
                                        # Log recent history
                                        if self._noise_floor_history:
                                            logger.info(f"Recent noise floor history: {[f'{x:.1f}' for x in self._noise_floor_history[-5:]]}")
                                
                                # Update tracking
                                self._last_noise_floor = noise_floor
                                self._noise_floor_history.append(noise_floor)
                                if len(self._noise_floor_history) > 10:
                                    self._noise_floor_history.pop(0)
                                
                                # More detailed logging every 5 seconds, basic every 1 second
                                if rx_check_count % 500 == 0:
                                    # Detailed diagnostic every 5 seconds
                                    diag_summary = self._collect_radio_diagnostics()
                                    key_info = {
                                        "noise": f"{noise_floor:.1f}dBm",
                                        "mode": diag_summary.get("radio_mode", "unknown"),
                                        "irq": diag_summary.get("irq_status", "unknown"),
                                        "busy": diag_summary.get("busy_status", "unknown")
                                    }
                                    logger.debug(f"[RX Task] Status check #{rx_check_count}: {key_info}")
                                else:
                                    # Basic logging every 1 second
                                    logger.debug(f"[RX Task] Check #{rx_check_count}, Noise: {noise_floor:.1f}dBm")
                            else:
                                logger.debug(f"[RX Task] Status check #{rx_check_count}, Noise: N/A")
                        except Exception as e:
                            logger.debug(f"[RX Task] Status check #{rx_check_count}, Noise read error: {e}")
            else:
                await asyncio.sleep(0.1)  # Longer delay when interrupts not set up

    def begin(self) -> bool:
        """Initialize the SX1262 radio module. Returns True if successful, False otherwise."""
        # Prevent double initialization
        if self._initialized:
            logger.debug("SX1262 radio already initialized, skipping")
            return True

        try:
            logger.debug("Initializing SX1262 radio...")
            # Create SX126x instance
            self.lora = SX126x()

            # Try IRQ setup - this is REQUIRED, no polling fallback
            try:
                self.irq_pin = Button(self.irq_pin_number, pull_up=False)
                self.irq_pin.when_activated = self._handle_interrupt
                self._interrupt_setup = True
                logger.debug(f"[RX] IRQ setup successful on pin {self.irq_pin_number}")
            except Exception as e:
                logger.error(f"IRQ setup failed: {e}")
                raise RuntimeError(f"Failed to set up IRQ pin {self.irq_pin_number}: {e}")

            # SPI and GPIO Pins setting
            self.lora.setSpi(self.bus_id, self.cs_id)
            if self.cs_pin != -1:
                # Override CS pin for special boards (e.g., Waveshare HAT)
                self.lora.setManualCsPin(self.cs_pin)

            # Don't call setPins! It creates duplicate GPIO objects that conflict
            # with our Button/GPIOManager
            # Instead, manually set the pin variables the SX126x needs
            self.lora._reset = self.reset_pin
            self.lora._busy = self.busy_pin
            self.lora._irq = self.irq_pin_number
            self.lora._txen = self.txen_pin
            self.lora._rxen = self.rxen_pin
            self.lora._wake = -1  # Not used

            # Setup TXEN pin if needed
            if self.txen_pin != -1 and not self._txen_pin_setup:
                if self._gpio_manager.setup_output_pin(self.txen_pin, initial_value=False):
                    self._txen_pin_setup = True
                else:
                    logger.warning(f"Could not setup TXEN pin {self.txen_pin}")

            # Adaptive initialization based on board type
            if self.is_waveshare:  # Waveshare HAT - use minimal initialization
                # Basic radio setup
                if not self._basic_radio_setup():
                    return False

                self.lora._fixResistanceAntenna()

                rfFreq = int(self.frequency * 33554432 / 32000000)
                self.lora.setRfFrequency(rfFreq)

                self.lora.setBufferBaseAddress(0x00, 0x80)  # TX=0x00, RX=0x80

                # Enable LDRO if symbol duration > 16ms (SF11/62.5kHz = 32.768ms)
                symbol_duration_ms = (2**self.spreading_factor) / (self.bandwidth / 1000)
                ldro = symbol_duration_ms > 16.0
                logger.info(
                    f"LDRO {'enabled' if ldro else 'disabled'} "
                    f"(symbol duration: {symbol_duration_ms:.3f}ms)"
                )
                self.lora.setLoRaModulation(
                    self.spreading_factor, self.bandwidth, self.coding_rate, ldro
                )

                self.lora.setLoRaPacket(
                    self.lora.HEADER_EXPLICIT,
                    self.preamble_length,
                    64,  # Initial payload length
                    True,  # CRC on
                    False,  # IQ standard
                )

                self.lora.setPaConfig(0x02, 0x03, 0x00, 0x01)
                self.lora.setTxParams(self.tx_power, self.lora.PA_RAMP_200U)

                # Configure RX interrupts (critical for RX functionality!)
                rx_mask = self._get_rx_irq_mask()
                self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
                self.lora.clearIrqStatus(0xFFFF)

            else:  # ClockworkPi or other boards - use full initialization
                # Reset RF module and set to standby
                if not self._basic_radio_setup(use_busy_check=True):
                    return False

                # Configure TCXO, regulator, calibration and RF switch
                self.lora.setDio3TcxoCtrl(self.lora.DIO3_OUTPUT_1_8, self.lora.TCXO_DELAY_5)
                self.lora.setRegulatorMode(self.lora.REGULATOR_DC_DC)
                self.lora.calibrate(0x7F)
                self.lora.setDio2RfSwitch()

                # Set packet type and frequency
                rfFreq = int(self.frequency * 33554432 / 32000000)
                self.lora.setRfFrequency(rfFreq)

                # Set RX gain and TX power
                self.lora.writeRegister(self.lora.REG_RX_GAIN, [self.lora.RX_GAIN_POWER_SAVING], 1)
                self.lora.setPaConfig(0x02, 0x03, 0x00, 0x01)
                self.lora.setTxParams(self.tx_power, self.lora.PA_RAMP_200U)

                # Configure modulation and packet parameters
                # Enable LDRO if symbol duration > 16ms (SF11/62.5kHz = 32.768ms)
                symbol_duration_ms = (2**self.spreading_factor) / (self.bandwidth / 1000)
                ldro = symbol_duration_ms > 16.0
                logger.info(
                    f"LDRO {'enabled' if ldro else 'disabled'} "
                    f"(symbol duration: {symbol_duration_ms:.3f}ms)"
                )
                self.lora.setLoRaModulation(
                    self.spreading_factor, self.bandwidth, self.coding_rate, ldro
                )
                self.lora.setPacketParamsLoRa(
                    self.preamble_length,
                    self.lora.HEADER_EXPLICIT,
                    64,  # Initial payload length
                    self.lora.CRC_ON,
                    self.lora.IQ_STANDARD,
                )

                # Configure RX interrupts
                rx_mask = self._get_rx_irq_mask()
                self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
                self.lora.clearIrqStatus(0xFFFF)

            # Set to RX continuous mode for initial operation
            self.lora.setRx(self.lora.RX_CONTINUOUS)
            self._initialized = True
            logger.info("SX1262 radio initialized successfully")

            # Perform AGC reset at startup to ensure clean noise floor readings
            logger.info("Performing startup AGC reset")
            if self.reset_agc():
                logger.info("Startup AGC reset successful")
            else:
                logger.warning("Startup AGC reset failed - continuing anyway")

            # Start RX IRQ background handler if using interrupts (only once)
            try:
                if self._interrupt_setup:
                    # Check if task is already running to prevent duplicates
                    if (
                        not hasattr(self, "_rx_irq_task")
                        or self._rx_irq_task is None
                        or self._rx_irq_task.done()
                    ):
                        try:
                            loop = asyncio.get_running_loop()
                        except RuntimeError:
                            # No event loop running, we'll start the task later
                            # when one is available
                            return True

                        self._rx_irq_task = loop.create_task(self._rx_irq_background_task())
                        logger.debug("[RX] RX IRQ background task started")
                    else:
                        logger.debug("[RX] RX IRQ background task already running")
            except Exception as e:
                logger.warning(f"Failed to start RX IRQ background handler: {e}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize SX1262 radio: '{e}'")
            self._initialized = False
            # Hard fail immediately - no retries
            raise RuntimeError(f"Failed to initialize SX1262 radio: {e}") from e

    def _calculate_tx_timeout(self, packet_length: int) -> tuple[int, int]:
        """Calculate transmission timeout based on modulation parameters"""
        sf = self.spreading_factor
        bw = self.bandwidth

        # Realistic timeout calculation based on actual LoRa performance
        if sf == 11 and bw == 250000:
            # Your specific configuration: SF11/250kHz
            base_tx_time_ms = 500 + (packet_length * 8)  # ~500ms + 8ms per byte
        elif sf == 7 and bw == 125000:
            # Standard configuration
            base_tx_time_ms = 100 + (packet_length * 2)  # ~100ms + 2ms per byte
        else:
            # General formula for other configurations
            sf_factor = 2 ** (sf - 7)
            bw_factor = 125000.0 / bw
            base_tx_time_ms = int(100 * sf_factor * bw_factor + (packet_length * sf_factor))

        # Add reasonable safety margin (2x) for timeout
        safety_margin = 2.0
        final_timeout_ms = int(base_tx_time_ms * safety_margin)

        # Reasonable limits: minimum 1 second, maximum 10 seconds
        final_timeout_ms = max(1000, min(final_timeout_ms, 10000))

        # Convert to driver timeout format
        driver_timeout = final_timeout_ms * 64  # tOut = timeout * 64

        return final_timeout_ms, driver_timeout

    def _prepare_packet_transmission(self, data_list: list, length: int) -> None:
        """Prepare radio for packet transmission"""
        # Set buffer base address
        self.lora.setBufferBaseAddress(0x00, 0x80)

        # Write the message to buffer
        self.lora.writeBuffer(0x00, data_list, length)

        # Configure packet parameters for this transmission
        headerType = self.lora.HEADER_EXPLICIT
        preambleLength = self.preamble_length
        crcType = self.lora.CRC_ON
        invertIq = self.lora.IQ_STANDARD

        self.lora.setPacketParamsLoRa(preambleLength, headerType, length, crcType, invertIq)

    def _setup_tx_interrupts(self) -> None:
        """Configure interrupts for transmission"""
        # Set up TX interrupt
        mask = self._get_tx_irq_mask()
        self.lora.setDioIrqParams(mask, mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)

        # Clear any existing interrupt flags before starting
        existing_irq = self.lora.getIrqStatus()
        if existing_irq != 0:
            self.lora.clearIrqStatus(existing_irq)

    async def _prepare_radio_for_tx(self) -> bool:
        """Prepare radio hardware for transmission. Returns True if successful."""
        # Clear the TX done event before starting transmission
        self._tx_done_event.clear()

        # Ensure radio is in standby before TX setup
        self.lora.setStandby(self.lora.STANDBY_RC)
        if self.lora.busyCheck():
            busy_wait = 0
            while self.lora.busyCheck() and busy_wait < 20:
                await asyncio.sleep(0.01)
                busy_wait += 1

        # Set TXEN/RXEN pins for TX mode
        self._control_tx_rx_pins(tx_mode=True)

        # Check busy status before starting transmission
        if self.lora.busyCheck():
            logger.warning("Radio is busy before starting transmission")
            # Wait for radio to become ready
            busy_timeout = 0
            while self.lora.busyCheck() and busy_timeout < 100:
                await asyncio.sleep(0.01)
                busy_timeout += 1
            if self.lora.busyCheck():
                logger.error("Radio stayed busy - cannot start transmission")
                return False

        return True

    def _control_tx_rx_pins(self, tx_mode: bool) -> None:
        """Control TXEN/RXEN pins for TX or RX mode"""
        if tx_mode:
            # Control TX mode pins
            if self.txen_pin != -1 and self._txen_pin_setup:
                self._gpio_manager.set_pin_high(self.txen_pin)
            if self.rxen_pin != -1:
                if not hasattr(self, "_rxen_pin_setup") or not self._rxen_pin_setup:
                    if self._gpio_manager.setup_output_pin(self.rxen_pin, initial_value=True):
                        self._rxen_pin_setup = True
                    else:
                        logger.warning(f"Could not setup RXEN pin {self.rxen_pin}")
                self._gpio_manager.set_pin_low(self.rxen_pin)
        else:
            # Control RX mode pins
            if self.txen_pin != -1 and self._txen_pin_setup:
                self._gpio_manager.set_pin_low(self.txen_pin)
            if self.rxen_pin != -1 and hasattr(self, "_rxen_pin_setup") and self._rxen_pin_setup:
                self._gpio_manager.set_pin_high(self.rxen_pin)

    async def _execute_transmission(self, driver_timeout: int) -> bool:
        """Execute the actual transmission. Returns True if successful."""
        # Start transmission
        self.lora.setTx(driver_timeout)

        # Check if radio accepted the TX command (wait for busy to clear)
        busy_timeout = 0
        while self.lora.busyCheck() and busy_timeout < 50:  # 500ms max wait
            await asyncio.sleep(0.01)
            busy_timeout += 1

        if self.lora.busyCheck():
            logger.error("Radio stayed busy after TX command - transmission may not have started")
            return False

        # Check initial interrupt status immediately after TX command
        initial_status = self.lora.getIrqStatus()

        # Check for critical errors
        if initial_status == 0xFFFF:
            logger.error(
                "Critical: Radio reporting all interrupt flags set - hardware communication failure"
            )
            return False

        elif initial_status & self.lora.IRQ_TIMEOUT:
            logger.error(
                "TX_TIMEOUT detected immediately after TX command - radio configuration issue"
            )
            self.lora.clearIrqStatus(initial_status)
            return False
        elif initial_status != 0:
            logger.warning(f"Unexpected initial interrupt status: 0x{initial_status:04X}")
            # Clear any unexpected flags but continue
            self.lora.clearIrqStatus(initial_status)

        return True

    async def _wait_for_transmission_complete(self, timeout_seconds: float) -> bool:
        """Wait for transmission to complete using interrupts. Returns True if successful."""
        logger.debug(f"[TX] Waiting for TX completion (timeout: {timeout_seconds}s)")
        start_time = time.time()

        # IRQ setup is required
        try:
            await asyncio.wait_for(self._tx_done_event.wait(), timeout=timeout_seconds)
            logger.debug("[TX] TX completion interrupt received!")
            return True
        except asyncio.TimeoutError:
            logger.error("[TX] TX completion timeout - no interrupt received!")
            await self._handle_transmission_timeout(timeout_seconds, start_time)
            return False

    async def _handle_transmission_timeout(self, timeout_seconds: float, start_time: float) -> None:
        """Handle transmission timeout and provide diagnostic information"""
        logger.error(
            f"Transmission wait timed out after {timeout_seconds:.1f} seconds - "
            f"radio may not be transmitting"
        )

        # Check interrupt status to see what happened
        irqStat = self.lora.getIrqStatus()
        logger.error(f"Interrupt status at timeout: 0x{irqStat:04X}")

        # Check if this is a configuration issue
        if irqStat == 0x0200:  # Only timeout bit set
            logger.error("Radio configuration issue: TX operation timed out without starting")

        self.lora.clearIrqStatus(irqStat)

    def _finalize_transmission(self) -> None:
        """Finalize transmission by checking status and logging results"""
        # Get final interrupt status
        irqStat = self.lora.getIrqStatus()

        # Check what actually happened
        logger.debug(f"Final interrupt status: 0x{irqStat:04X}")

        if irqStat & self.lora.IRQ_TX_DONE:
            pass  # Success
        elif irqStat & self.lora.IRQ_TIMEOUT:
            logger.warning("TX_TIMEOUT interrupt received - transmission failed")
        else:
            logger.warning(f"Unexpected interrupt status: 0x{irqStat:04X}")

        # Get transmission stats if available
        try:
            tx_time = self.lora.transmitTime()
            if tx_time > 0:
                data_rate = self.lora.dataRate()
                logger.debug(f"Packet transmitted: {tx_time:.2f}ms, {data_rate:.2f} bytes/s")
        except Exception as e:
            logger.debug(f"Transmission stats not available: {e}")

        # Clear interrupt status
        self.lora.clearIrqStatus(irqStat)

        # Reset TX/RX enable pins after transmission
        self._control_tx_rx_pins(tx_mode=False)

    async def _restore_rx_mode(self) -> None:
        """Restore radio to RX continuous mode after transmission"""
        try:
            if self.lora:
                logger.debug("[TX→RX] Starting TX to RX mode transition with AGC restoration")
                
                # Add a small delay to ensure radio is ready to transition to RX
                await asyncio.sleep(0.01)
                
                # CRITICAL: Force AGC recalibration during TX→RX transition
                # This prevents the AGC corruption that causes stuck noise floor readings
                try:
                    # Set to standby first
                    self.lora.setStandby(self.lora.STANDBY_RC)
                    await asyncio.sleep(0.05)  # Let radio settle
                    
                    # Recalibrate AGC - this is the key fix
                    self.lora.calibrate(0x7F)  # Full calibration including AGC
                    logger.debug("[TX→RX] AGC recalibration completed")
                    
                    # Set RF switch back to RX mode
                    self._control_tx_rx_pins(tx_mode=False)
                    
                except Exception as e:
                    logger.warning(f"[TX→RX] AGC recalibration failed: {e}")

                # Reconfigure RX interrupts before setting RX mode
                rx_mask = self._get_rx_irq_mask()
                self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)

                self.lora.setRx(self.lora.RX_CONTINUOUS)

                # Verify the radio actually entered RX mode
                await asyncio.sleep(0.01)

                # Clear any pending interrupt flags to ensure clean RX state
                irqStat = self.lora.getIrqStatus()
                if irqStat != 0:
                    self.lora.clearIrqStatus(irqStat)
                
                logger.debug("[TX→RX] TX to RX mode transition completed with AGC restoration")

        except Exception as e:
            logger.warning(f"Failed to set RX mode after TX: {e}")

    async def send(self, data: bytes) -> None:
        """Send a packet asynchronously"""
        if not self._initialized or self.lora is None:
            logger.error("Radio not initialized")
            return

        async with self._tx_lock:
            try:
                # Convert bytes to list of integers
                data_list = list(data)
                length = len(data_list)

                # Calculate transmission timeout
                final_timeout_ms, driver_timeout = self._calculate_tx_timeout(length)
                timeout_seconds = (final_timeout_ms / 1000.0) + 3.0  # Add 3 seconds buffer

                # Prepare packet for transmission
                self._prepare_packet_transmission(data_list, length)

                # Setup TX interrupts
                self._setup_tx_interrupts()

                # Small delay to ensure IRQ configuration is applied
                await asyncio.sleep(self.RADIO_TIMING_DELAY)

                logger.debug(
                    f"Setting TX timeout: {final_timeout_ms}ms "
                    f"(tOut={driver_timeout}) for {length} bytes"
                )

                # Prepare radio hardware for transmission
                if not await self._prepare_radio_for_tx():
                    return

                # Execute the transmission
                if not await self._execute_transmission(driver_timeout):
                    return

                # Wait for transmission to complete
                if not await self._wait_for_transmission_complete(timeout_seconds):
                    return

                # Finalize transmission and log results
                self._finalize_transmission()

            except Exception as e:
                logger.error(f"Failed to send packet: {e}")
                return
            finally:
                # Always leave radio in RX continuous mode after TX
                await self._restore_rx_mode()

    async def wait_for_rx(self) -> bytes:
        """Not implemented: use set_rx_callback instead."""
        raise NotImplementedError(
            "Use set_rx_callback(callback) to receive packets asynchronously."
        )

    def sleep(self) -> None:
        """Put the radio into low-power sleep mode"""
        if self._initialized and self.lora:
            try:
                self.lora.sleep()
                logger.debug("Radio in sleep mode")
            except Exception as e:
                logger.error(f"Failed to put radio to sleep: {e}")

    def get_last_rssi(self) -> int:
        """Return last received RSSI in dBm"""
        return self.last_rssi

    def get_last_snr(self) -> float:
        """Return last received SNR in dB"""
        return self.last_snr

    def get_noise_floor(self) -> Optional[float]:
        """
        Get current noise floor (instantaneous RSSI) in dBm.
        Returns None if radio is not initialized or if reading fails.
        """
        if not self._initialized or self.lora is None:
            return None
        
        # Skip noise floor reading if we're currently transmitting
        if hasattr(self, '_tx_lock') and self._tx_lock.locked():
            return None
            
        try:
            raw_rssi = self.lora.getRssiInst()
            if raw_rssi is not None:
                noise_floor_dbm = -(float(raw_rssi) / 2)
                # Validate reading - reject obviously invalid values
                if -150.0 <= noise_floor_dbm <= -50.0:
                    return noise_floor_dbm
                else:
                    # Invalid reading detected - trigger radio state reset
                    logger.debug(f"Invalid noise floor reading: {noise_floor_dbm:.1f}dBm - resetting radio")
                    self._reset_radio_state()
                    return None
            return None
        except Exception as e:
            logger.debug(f"Failed to read noise floor: {e}")
            return None

    def _collect_radio_diagnostics(self) -> dict:
        """
        Collect comprehensive radio diagnostics for debugging noise floor corruption.
        Returns a dictionary with various radio parameters and status information.
        """
        diag = {"timestamp": time.time()}
        
        if not self._initialized or self.lora is None:
            diag["error"] = "Radio not initialized"
            return diag
            
        try:
            # Basic radio mode and status
            try:
                diag["radio_mode"] = self.lora.getMode()
            except Exception as e:
                diag["radio_mode_error"] = str(e)
                
            try:
                diag["irq_status"] = f"0x{self.lora.getIrqStatus():04X}"
            except Exception as e:
                diag["irq_status_error"] = str(e)
                
            try:
                diag["busy_status"] = self.lora.busyCheck()
            except Exception as e:
                diag["busy_status_error"] = str(e)
            
            # RF parameters and readings
            try:
                # Multiple RSSI readings to check consistency
                rssi_readings = []
                for i in range(3):
                    raw_rssi = self.lora.getRssiInst()
                    if raw_rssi is not None:
                        rssi_readings.append(-(float(raw_rssi) / 2))
                    time.sleep(0.01)  # Small delay between readings
                diag["rssi_readings"] = [f"{r:.1f}" for r in rssi_readings]
                if rssi_readings:
                    diag["rssi_variance"] = f"{max(rssi_readings) - min(rssi_readings):.1f}"
            except Exception as e:
                diag["rssi_error"] = str(e)
                
            # Current radio configuration
            try:
                diag["frequency"] = f"{self.frequency/1e6:.3f}MHz"
                diag["bandwidth"] = f"{self.bandwidth/1000:.0f}kHz"
                diag["spreading_factor"] = self.spreading_factor
                diag["tx_power"] = f"{self.tx_power}dBm"
            except Exception as e:
                diag["config_error"] = str(e)
                
            # GPIO pin states (if accessible)
            try:
                pin_states = {}
                if self._txen_pin_setup and self.txen_pin != -1:
                    try:
                        pin_states["txen"] = "high" if self._gpio_manager._pins[self.txen_pin].value else "low"
                    except:
                        pin_states["txen"] = "unknown"
                        
                if hasattr(self, "_rxen_pin_setup") and self._rxen_pin_setup and self.rxen_pin != -1:
                    try:
                        pin_states["rxen"] = "high" if self._gpio_manager._pins[self.rxen_pin].value else "low"
                    except:
                        pin_states["rxen"] = "unknown"
                        
                if pin_states:
                    diag["gpio_pins"] = pin_states
            except Exception as e:
                diag["gpio_error"] = str(e)
                
            # Register readings (if available) - focus on AGC-related registers
            try:
                # Try to read some key registers that might indicate AGC issues
                # Note: These may not be available in all driver versions
                if hasattr(self.lora, 'readRegister'):
                    try:
                        # RX gain register (most important for AGC issues)
                        rx_gain = self.lora.readRegister(self.lora.REG_RX_GAIN, 1)
                        if rx_gain:
                            diag["rx_gain_reg"] = f"0x{rx_gain[0]:02X}"
                    except:
                        pass
                        
                    try:
                        # Random number generator (indicates RF activity)
                        random_reg = self.lora.readRegister(0x0819, 1)  # Random number register
                        if random_reg:
                            diag["random_reg"] = f"0x{random_reg[0]:02X}"
                    except:
                        pass
                        
                    try:
                        # AGC-related registers for SX1262
                        # Register 0x0891: AGC control
                        agc_ctrl = self.lora.readRegister(0x0891, 1)
                        if agc_ctrl:
                            diag["agc_ctrl_reg"] = f"0x{agc_ctrl[0]:02X}"
                    except:
                        pass
                        
                    try:
                        # Register 0x0892: AGC configuration 
                        agc_config = self.lora.readRegister(0x0892, 1)
                        if agc_config:
                            diag["agc_config_reg"] = f"0x{agc_config[0]:02X}"
                    except:
                        pass
                        
                    try:
                        # Register 0x089B: LNA gain setting
                        lna_gain = self.lora.readRegister(0x089B, 1)
                        if lna_gain:
                            diag["lna_gain_reg"] = f"0x{lna_gain[0]:02X}"
                    except:
                        pass
                        
                    try:
                        # Register 0x08AC: Manual gain setting
                        manual_gain = self.lora.readRegister(0x08AC, 1)
                        if manual_gain:
                            diag["manual_gain_reg"] = f"0x{manual_gain[0]:02X}"
                    except:
                        pass
            except Exception as e:
                diag["register_error"] = str(e)
                
            # Packet statistics if available
            try:
                if hasattr(self, 'last_rssi') and hasattr(self, 'last_snr'):
                    diag["last_packet"] = {"rssi": self.last_rssi, "snr": self.last_snr}
            except Exception as e:
                diag["packet_stats_error"] = str(e)
                
            # Lock states
            try:
                diag["tx_locked"] = self._tx_lock.locked() if hasattr(self, '_tx_lock') else False
                diag["rx_locked"] = self._rx_lock.locked() if hasattr(self, '_rx_lock') else False
            except Exception as e:
                diag["lock_error"] = str(e)
                
        except Exception as e:
            diag["collection_error"] = str(e)
            
        return diag

    def _reset_radio_state(self) -> None:
        """Reset radio state to recover from invalid RSSI readings"""
        if not self._initialized or self.lora is None:
            return
            
        try:
            # Force radio back to standby then RX mode
            self.lora.setStandby(self.lora.STANDBY_RC)
            time.sleep(0.05)  # Let radio settle
            
            # Clear interrupt flags
            irq_status = self.lora.getIrqStatus()
            if irq_status != 0:
                self.lora.clearIrqStatus(irq_status)
            
            # Restore RX mode
            rx_mask = self._get_rx_irq_mask()
            self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
            self.lora.setRx(self.lora.RX_CONTINUOUS)
            
            logger.debug("Radio state reset completed")
        except Exception as e:
            logger.warning(f"Failed to reset radio state: {e}")

    async def _restore_agc_system(self) -> bool:
        """
        Advanced AGC system restoration using complete radio reset when AGC registers are corrupted.
        This addresses the root cause of persistent noise floor corruption by performing a full reset cycle.
        Returns True if restoration was successful.
        """
        if not self._initialized or self.lora is None:
            logger.warning("Cannot restore AGC system - radio not initialized")
            return False
            
        try:
            logger.info("Starting complete radio reset for AGC restoration")
            
            # Record pre-restoration noise floor for comparison
            pre_noise = self.get_noise_floor()
            logger.info(f"Pre-restoration noise floor: {pre_noise:.1f}dBm" if pre_noise else "Pre-restoration noise floor: N/A")
            
            # APPROACH: Complete radio reset cycle rather than just calibration
            # The AGC registers seem to be protected and won't update with just calibration
            
            # Step 1: Complete hardware reset using the reset pin
            logger.debug("Performing complete hardware reset via reset pin")
            try:
                self.lora.reset()  # Hardware reset via reset pin
                await asyncio.sleep(0.2)  # Extended reset time
                logger.debug("Hardware reset completed")
            except Exception as e:
                logger.warning(f"Hardware reset failed: {e}")
            
            # Step 2: Re-initialize radio from scratch (like begin() but focused on AGC)
            logger.debug("Re-initializing radio configuration from scratch")
            
            # Force standby mode multiple times
            for i in range(3):
                self.lora.setStandby(self.lora.STANDBY_RC)
                await asyncio.sleep(0.05)
                
                # Verify standby mode was achieved
                try:
                    mode = self.lora.getMode()
                    if mode == self.lora.STATUS_MODE_STDBY_RC:
                        logger.debug(f"Standby mode confirmed (attempt {i+1})")
                        break
                    else:
                        logger.debug(f"Standby mode not achieved, retrying (mode: {mode})")
                except:
                    pass
            
            # Step 3: Set packet type (required before other operations)
            self.lora.setPacketType(self.lora.LORA_MODEM)
            await asyncio.sleep(0.02)
            
            # Step 4: Board-specific complete re-initialization
            if not self.is_waveshare:
                logger.debug("Performing complete non-Waveshare re-initialization")
                
                # Complete TCXO and regulator setup
                self.lora.setDio3TcxoCtrl(self.lora.DIO3_OUTPUT_1_8, self.lora.TCXO_DELAY_5)
                await asyncio.sleep(0.05)  # Extended TCXO startup time
                
                self.lora.setRegulatorMode(self.lora.REGULATOR_DC_DC)
                await asyncio.sleep(0.05)
                
                # Extended calibration sequence
                logger.debug("Performing extended calibration sequence")
                self.lora.calibrate(0x7F)  # Full calibration
                await asyncio.sleep(0.2)  # Extended calibration time
                
                # Additional calibrations to ensure AGC reset
                try:
                    self.lora.calibrate(0x01)  # Image calibration (AGC-related)
                    await asyncio.sleep(0.1)
                    self.lora.calibrate(0x02)  # ADC calibration if available
                    await asyncio.sleep(0.1)
                except:
                    pass
                
                self.lora.setDio2RfSwitch()
                await asyncio.sleep(0.02)
                
                # Step 5: Complete RF configuration reset
                logger.debug("Resetting complete RF configuration")
                
                # Frequency setup
                rfFreq = int(self.frequency * 33554432 / 32000000)
                self.lora.setRfFrequency(rfFreq)
                await asyncio.sleep(0.02)
                
                # Power amplifier setup (affects AGC)
                self.lora.setPaConfig(0x02, 0x03, 0x00, 0x01)
                self.lora.setTxParams(self.tx_power, self.lora.PA_RAMP_200U)
                await asyncio.sleep(0.02)
                
                # Step 6: Force AGC register writes with extended verification
                logger.debug("Attempting forced AGC register restoration")
                
                # Multiple attempts to write RX gain register
                for attempt in range(3):
                    try:
                        self.lora.writeRegister(self.lora.REG_RX_GAIN, (self.lora.RX_GAIN_POWER_SAVING,), 1)
                        await asyncio.sleep(0.02)
                        
                        # Extended verification
                        verify_reg = self.lora.readRegister(self.lora.REG_RX_GAIN, 1)
                        if verify_reg and verify_reg[0] != 0x00:
                            logger.debug(f"RX gain register restored (attempt {attempt+1}): 0x{verify_reg[0]:02X}")
                            break
                        else:
                            logger.debug(f"RX gain register write failed (attempt {attempt+1})")
                    except Exception as e:
                        logger.debug(f"RX gain register write error (attempt {attempt+1}): {e}")
                        
                    if attempt == 2:
                        logger.warning("All RX gain register write attempts failed")
                        
            else:
                # Waveshare complete re-initialization
                logger.debug("Performing complete Waveshare re-initialization")
                
                # Extended resistance fix
                self.lora._fixResistanceAntenna()
                await asyncio.sleep(0.05)
                
                # Extended calibration
                self.lora.calibrate(0x7F)
                await asyncio.sleep(0.2)
                
                # Frequency setup
                rfFreq = int(self.frequency * 33554432 / 32000000)
                self.lora.setRfFrequency(rfFreq)
                await asyncio.sleep(0.02)
            
            # Step 7: Complete modulation parameter reset
            logger.debug("Resetting modulation parameters")
            symbol_duration_ms = (2**self.spreading_factor) / (self.bandwidth / 1000)
            ldro = symbol_duration_ms > 16.0
            
            self.lora.setLoRaModulation(
                self.spreading_factor, self.bandwidth, self.coding_rate, ldro
            )
            await asyncio.sleep(0.05)
            
            # Step 8: Complete packet parameter reset
            if not self.is_waveshare:
                self.lora.setPacketParamsLoRa(
                    self.preamble_length,
                    self.lora.HEADER_EXPLICIT,
                    64,  # Initial payload length
                    self.lora.CRC_ON,
                    self.lora.IQ_STANDARD,
                )
            else:
                self.lora.setLoRaPacket(
                    self.lora.HEADER_EXPLICIT,
                    self.preamble_length,
                    64,  # Initial payload length
                    True,  # CRC on
                    False,  # IQ standard
                )
            await asyncio.sleep(0.02)
            
            # Step 9: Complete interrupt system reset
            logger.debug("Resetting interrupt system")
            self.lora.clearIrqStatus(0xFFFF)
            await asyncio.sleep(0.02)
            
            rx_mask = self._get_rx_irq_mask()
            self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
            await asyncio.sleep(0.02)
            
            # Step 10: Set RF switch pins properly
            self._control_tx_rx_pins(tx_mode=False)
            await asyncio.sleep(0.05)
            
            # Step 11: Final RX mode setup with extended settling
            logger.debug("Setting final RX mode with extended settling")
            self.lora.setRx(self.lora.RX_CONTINUOUS)
            await asyncio.sleep(0.2)  # Extended settling time
            
            # Verify radio mode
            mode = self.lora.getMode()
            if mode == 80:  # RX continuous mode
                logger.debug("Radio confirmed in RX continuous mode after reset")
            else:
                logger.warning(f"Radio not in expected RX mode after reset (mode: {mode})")
            
            # Step 12: Extended AGC settling with progressive monitoring
            logger.debug("Allowing extended AGC settling after complete reset...")
            best_noise = None
            for i in range(10):  # Extended settling period
                await asyncio.sleep(0.1)
                current_noise = self.get_noise_floor()
                if current_noise:
                    if best_noise is None or current_noise < best_noise:
                        best_noise = current_noise
                    if current_noise < -100.0:
                        logger.debug(f"AGC stabilized at good level: {current_noise:.1f}dBm (cycle {i+1})")
                        break
                    elif i % 3 == 0:  # Log every 3rd check
                        logger.debug(f"AGC settling: {current_noise:.1f}dBm (cycle {i+1})")
            
            # Final verification
            post_noise = self.get_noise_floor()
            logger.info(f"Post-reset noise floor: {post_noise:.1f}dBm" if post_noise else "Post-reset noise floor: N/A")
            
            # Success determination
            success = False
            if post_noise:
                if post_noise < -100.0:
                    success = True
                    logger.info(f"Complete radio reset successful - AGC restored to healthy level: {post_noise:.1f}dBm")
                elif pre_noise and abs(post_noise - pre_noise) > 10.0:
                    success = True
                    logger.info(f"Complete radio reset partially successful: {pre_noise:.1f} -> {post_noise:.1f}dBm")
                else:
                    logger.warning(f"Complete radio reset ineffective - noise floor still problematic: {post_noise:.1f}dBm")
            
            # Log register status after reset for comparison
            try:
                diag = self._collect_radio_diagnostics()
                agc_regs = {
                    "rx_gain": diag.get("rx_gain_reg", "N/A"),
                    "agc_ctrl": diag.get("agc_ctrl_reg", "N/A"),
                    "agc_config": diag.get("agc_config_reg", "N/A")
                }
                logger.info(f"Post-reset AGC registers: {agc_regs}")
            except:
                pass
            
            logger.info("Complete radio reset sequence finished")
            return success
            
        except Exception as e:
            logger.error(f"Failed to perform complete radio reset: {e}")
            return False

    def reset_agc(self) -> bool:
        """
        Manually reset the AGC (Automatic Gain Control) to recover from stuck noise floor readings.
        Call this method when noise floor readings appear stuck (e.g., -77dBm instead of -110dBm).
        Returns True if reset was successful.
        """
        if not self._initialized or self.lora is None:
            logger.warning("Cannot reset AGC - radio not initialized")
            return False
            
        try:
            logger.info("Performing manual AGC reset")
            
            # More aggressive reset for stuck AGC
            self.lora.setStandby(self.lora.STANDBY_RC)
            time.sleep(0.1)  # Longer settle time
            
            # Clear all interrupt flags
            self.lora.clearIrqStatus(0xFFFF)
            
            # Set RF switch to RX mode
            self._control_tx_rx_pins(tx_mode=False)
            
            # For non-Waveshare boards, perform full recalibration
            if not self.is_waveshare:
                # Full calibration sequence like initialization
                self.lora.setDio3TcxoCtrl(self.lora.DIO3_OUTPUT_1_8, self.lora.TCXO_DELAY_5)
                self.lora.setRegulatorMode(self.lora.REGULATOR_DC_DC)
                self.lora.calibrate(0x7F)  # Full calibration
                self.lora.setDio2RfSwitch()
            else:
                # Waveshare minimal recalibration
                self.lora._fixResistanceAntenna()
                self.lora.calibrate(0x7F)
            
            # Restore RX mode
            rx_mask = self._get_rx_irq_mask()
            self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
            self.lora.setRx(self.lora.RX_CONTINUOUS)
            
            time.sleep(0.1)  # Let everything settle
            logger.info("Manual AGC reset completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reset AGC: {e}")
            return False

    def set_frequency(self, frequency: int) -> bool:
        """Set operating frequency"""

        def set_freq():
            self.frequency = frequency
            self.lora.setFrequency(frequency)

        return self._safe_radio_operation(
            "set frequency", set_freq, f"Frequency set to {frequency/1e6:.1f} MHz"
        )

    def set_tx_power(self, power: int) -> bool:
        """Set TX power in dBm"""

        def set_power():
            self.tx_power = power
            self.lora.setTxPower(power, self.lora.TX_POWER_SX1262)

        return self._safe_radio_operation("set TX power", set_power, f"TX power set to {power} dBm")

    def set_spreading_factor(self, sf: int) -> bool:
        """Set spreading factor (6-12)"""

        def set_sf():
            self.spreading_factor = sf
            self.lora.setLoRaModulation(sf, self.bandwidth, self.coding_rate)

        return self._safe_radio_operation(
            "set spreading factor", set_sf, f"Spreading factor set to {sf}"
        )

    def set_bandwidth(self, bw: int) -> bool:
        """Set bandwidth in Hz"""

        def set_bw():
            self.bandwidth = bw
            self.lora.setLoRaModulation(self.spreading_factor, bw, self.coding_rate)

        return self._safe_radio_operation(
            "set bandwidth", set_bw, f"Bandwidth set to {bw/1000:.0f} kHz"
        )

    def get_status(self) -> dict:
        """Get radio status information"""
        status = {
            "initialized": self._initialized,
            "frequency": self.frequency,
            "tx_power": self.tx_power,
            "spreading_factor": self.spreading_factor,
            "bandwidth": self.bandwidth,
            "coding_rate": self.coding_rate,
            "last_rssi": self.last_rssi,
            "last_snr": self.last_snr,
        }

        if self._initialized and self.lora:
            try:
                # Add hardware-specific status if available
                status["hardware_ready"] = True
            except Exception as e:
                logger.debug(f"Could not get hardware status: {e}")
                status["hardware_ready"] = False

        return status
    



    def _get_thresholds_for_current_settings(self) -> tuple[int, int]:
        """Fetch CAD thresholds for the current spreading factor.
        Returns (cadDetPeak, cadDetMin).
        """

        # Default CAD thresholds by SF (based on Semtech TR013 recommendations)
        DEFAULT_CAD_THRESHOLDS = {
            7: (22, 10),
            8: (22, 10),
            9: (24, 10),
            10: (25, 10),
            11: (26, 10),
            12: (30, 10),
        }

        # Fall back to SF7 values if unknown
        return DEFAULT_CAD_THRESHOLDS.get(self.spreading_factor, (22, 10))




    async def perform_cad(
        self,
        det_peak: int | None = None,
        det_min: int | None = None,
        timeout: float = 1.0,
        calibration: bool = False,
    ) -> bool | dict:
        """
        Perform Channel Activity Detection (CAD).
        If calibration=True, uses provided thresholds and returns detailed info.
        If calibration=False, uses pre-calibrated/default thresholds.
        
        Returns:
            bool: Channel activity detected (when calibration=False)
            dict: Calibration data (when calibration=True)
        """
        if not self._initialized:
            raise RuntimeError("Radio not initialized")
        
        if not self.lora:
            raise RuntimeError("LoRa radio object not available")

        # Choose thresholds
        if det_peak is None or det_min is None:
            det_peak, det_min = self._get_thresholds_for_current_settings()
        
        try:
            # Clear any existing interrupt flags
            existing_irq = self.lora.getIrqStatus()
            if existing_irq != 0:
                self.lora.clearIrqStatus(existing_irq)
            
            # Clear CAD event before starting
            self._cad_event.clear()
            
            # Start CAD operation using the driver's start_cad method
            self.lora.start_cad(det_peak, det_min)

            # Wait for CAD completion
            try:
                await asyncio.wait_for(self._cad_event.wait(), timeout=timeout)
                self._cad_event.clear()
                
                # Read interrupt status
                irq = self.lora.getIrqStatus()
                self.lora.clearIrqStatus(irq)

                # Check for CAD detection
                cad_detected_flag = getattr(self.lora, 'IRQ_CAD_DETECTED', 0x4000)
                detected = bool(irq & cad_detected_flag)

                if calibration:
                    return {
                        "sf": self.spreading_factor,
                        "bw": self.bandwidth,
                        "det_peak": det_peak,
                        "det_min": det_min,
                        "detected": detected,
                        "timestamp": time.time(),
                        "irq_status": irq
                    }
                else:
                    return detected

            except asyncio.TimeoutError:
                logger.debug("CAD operation timed out")
                if calibration:
                    return {
                        "sf": self.spreading_factor,
                        "bw": self.bandwidth,
                        "det_peak": det_peak,
                        "det_min": det_min,
                        "detected": False,
                        "timestamp": time.time(),
                        "timeout": True
                    }
                else:
                    return False
                    
        except Exception as e:
            logger.error(f"CAD operation failed: {e}")
            if calibration:
                return {
                    "sf": self.spreading_factor,
                    "bw": self.bandwidth,
                    "det_peak": det_peak,
                    "det_min": det_min,
                    "detected": False,
                    "timestamp": time.time(),
                    "error": str(e)
                }
            else:
                return False
        finally:
            # Restore RX mode after CAD
            try:
                rx_mask = self._get_rx_irq_mask()
                self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
                self.lora.setRx(self.lora.RX_CONTINUOUS)
            except Exception as e:
                logger.warning(f"Failed to restore RX mode after CAD: {e}")



    def cleanup(self) -> None:
        """Clean up radio resources"""
        if hasattr(self, "lora") and self.lora:
            try:
                self.lora.end()
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")

        if hasattr(self, "_gpio_manager"):
            self._gpio_manager.cleanup_all()

        if hasattr(self, "irq_pin") and self.irq_pin:
            try:
                self.irq_pin.close()
            except Exception:
                pass

        self._interrupt_setup = False
        self._initialized = False

        if SX1262Radio._active_instance is self:
            SX1262Radio._active_instance = None

    @classmethod
    def get_instance(cls, **kwargs):
        """Get the active instance or create a new one (singleton-like behavior)"""
        if cls._active_instance is not None:
            return cls._active_instance
        else:
            return cls(**kwargs)


# Factory function for easy instantiation
def create_sx1262_radio(**kwargs) -> SX1262Radio:
    """Create and initialize an SX1262 radio instance"""
    radio = SX1262Radio(**kwargs)
    if radio.begin():
        return radio
    else:
        raise RuntimeError("Failed to initialize SX1262 radio")


# Example configuration for common setups
CONFIGS = {
    "eu868": {
        "frequency": 868000000,
        "tx_power": 14,
        "spreading_factor": 7,
        "bandwidth": 125000,
        "coding_rate": 5,
    },
    "us915": {
        "frequency": 915000000,
        "tx_power": 20,
        "spreading_factor": 7,
        "bandwidth": 125000,
        "coding_rate": 5,
    },
    "as923": {
        "frequency": 923000000,
        "tx_power": 16,
        "spreading_factor": 7,
        "bandwidth": 125000,
        "coding_rate": 5,
    },
}
