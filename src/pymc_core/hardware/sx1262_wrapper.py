"""
SX1262 LoRa Radio Driver for Raspberry Pi
Implements the LoRaRadio interface using the SX126x library


I have made some experimental changes to the cad section that I need to revisit.


"""

import asyncio
import logging
import math
import random
import time
from typing import Optional

from .base import LoRaRadio
from .gpio_manager import GPIOPinManager
from .lora.LoRaRF.SX126x import SX126x

logger = logging.getLogger("SX1262_wrapper")


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
        txled_pin: int = -1,
        rxled_pin: int = -1,
        frequency: int = 868000000,
        tx_power: int = 22,
        spreading_factor: int = 7,
        bandwidth: int = 125000,
        coding_rate: int = 5,
        preamble_length: int = 12,
        sync_word: int = 0x3444,
        is_waveshare: bool = False,
        use_dio3_tcxo: bool = False,
        dio3_tcxo_voltage: float = 1.8,
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
            txled_pin: GPIO pin for TX LED (default: -1 if not used)
            rxled_pin: GPIO pin for RX LED (default: -1 if not used)
            frequency: Operating frequency in Hz (default: 868MHz)
            tx_power: TX power in dBm (default: 22)
            spreading_factor: LoRa spreading factor (default: 7)
            bandwidth: Bandwidth in Hz (default: 125kHz)
            coding_rate: Coding rate (default: 5 for 4/5)
            preamble_length: Preamble length (default: 12)
            sync_word: Sync word (default: 0x3444 for public network)
            is_waveshare: Use alternate initialization needed for Waveshare HAT
            use_dio3_tcxo: Enable DIO3 TCXO control (default: False)
            dio3_tcxo_voltage: TCXO reference voltage in volts (default: 1.8)
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
        self.txled_pin = txled_pin
        self.rxled_pin = rxled_pin

        # Radio configuration
        self.frequency = frequency
        self.tx_power = tx_power
        self.spreading_factor = spreading_factor
        self.bandwidth = bandwidth
        self.coding_rate = coding_rate
        self.preamble_length = preamble_length
        self.sync_word = sync_word
        self.is_waveshare = is_waveshare
        self.use_dio3_tcxo = use_dio3_tcxo
        self.dio3_tcxo_voltage = dio3_tcxo_voltage

        # State variables
        self.lora: Optional[SX126x] = None
        self.last_rssi: int = -99
        self.last_snr: float = 0.0
        self._initialized = False
        self._rx_lock = asyncio.Lock()
        self._tx_lock = asyncio.Lock()

        # GPIO management
        self._gpio_manager = GPIOPinManager()
        self._interrupt_setup = False
        self._txen_pin_setup = False
        self._txled_pin_setup = False
        self._rxled_pin_setup = False

        self._tx_done_event = asyncio.Event()
        self._rx_done_event = asyncio.Event()
        self._cad_event = asyncio.Event()

        # Store last IRQ status for background task
        self._last_irq_status = 0

        # Custom CAD thresholds (None means use defaults)
        self._custom_cad_peak = None
        self._custom_cad_min = None

        # Noise floor sampling
        self._noise_floor = -99.0
        self._num_floor_samples = 0
        self._floor_sample_sum = 0.0
        self._last_packet_activity = 0.0
        self._is_receiving_packet = False
        self.NUM_NOISE_FLOOR_SAMPLES = 20
        self.SAMPLING_THRESHOLD = 10  # Only sample if RSSI < noise_floor + threshold

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
        """instance method interrupt handler"""

        try:
            if not self._initialized or not self.lora:
                logger.warning("Interrupt called but radio not initialized")
                return

            # Read IRQ status and handle
            irqStat = self.lora.getIrqStatus()

            # Clear ALL interrupts immediately to prevent interrupt storms
            if irqStat != 0:
                self.lora.clearIrqStatus(irqStat)

            # Store the status for the background task to read
            self._last_irq_status = irqStat

            # Handle TX_DONE
            if irqStat & self.lora.IRQ_TX_DONE:
                logger.debug("[TX] TX_DONE interrupt (0x{:04X})".format(self.lora.IRQ_TX_DONE))
                self._tx_done_event.set()

            # Handle CAD interrupts
            if irqStat & (self.lora.IRQ_CAD_DETECTED | self.lora.IRQ_CAD_DONE):
                cad_detected = bool(irqStat & self.lora.IRQ_CAD_DETECTED)
                cad_done = bool(irqStat & self.lora.IRQ_CAD_DONE)
                logger.debug(
                    f"[CAD] interrupt detected: {cad_detected}, done: {cad_done} (0x{irqStat:04X})"
                )
                if hasattr(self, "_cad_event"):
                    self._cad_event.set()

            # Handle RX interrupts
            rx_interrupts = self._get_rx_irq_mask()
            if irqStat & self.lora.IRQ_RX_DONE:
                logger.debug("[RX] RX_DONE interrupt (0x{:04X})".format(self.lora.IRQ_RX_DONE))
                if not self._tx_lock.locked():
                    self._rx_done_event.set()
                else:
                    logger.debug("[RX] Ignoring RX_DONE during TX operation")
            elif irqStat & self.lora.IRQ_CRC_ERR:
                logger.debug("[RX] CRC_ERR interrupt (0x{:04X})".format(self.lora.IRQ_CRC_ERR))
                if not self._tx_lock.locked():
                    self._rx_done_event.set()
                else:
                    logger.debug("[RX] Ignoring CRC_ERR during TX operation")
            elif irqStat & self.lora.IRQ_TIMEOUT:
                logger.debug("[RX] TIMEOUT interrupt (0x{:04X})".format(self.lora.IRQ_TIMEOUT))
                if not self._tx_lock.locked():
                    self._rx_done_event.set()
                else:
                    logger.debug("[RX] Ignoring TIMEOUT during TX operation")
            elif irqStat & rx_interrupts:
                logger.debug(f"[RX] Other RX interrupt detected: 0x{irqStat & rx_interrupts:04X}")
                if not self._tx_lock.locked():
                    self._rx_done_event.set()
                else:
                    logger.debug(
                        f"[RX] Ignoring spurious interrupt "
                        f"0x{irqStat & rx_interrupts:04X} during TX operation"
                    )

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
        while self._initialized:
            if self._interrupt_setup:
                # Wait for RX_DONE event
                try:
                    await asyncio.wait_for(
                        self._rx_done_event.wait(), timeout=self.RADIO_TIMING_DELAY
                    )
                    self._rx_done_event.clear()
                    logger.debug("[RX] RX_DONE event triggered!")

                    # Mark that we're processing a packet (prevents noise floor sampling)
                    self._is_receiving_packet = True
                    self._last_packet_activity = time.time()

                    try:
                        # Use the IRQ status stored by the interrupt handler
                        irqStat = self._last_irq_status
                        logger.debug(f"[RX] IRQ Status: 0x{irqStat:04X}")

                        # IRQ already cleared by interrupt handler, just process the packet
                        if irqStat & self.lora.IRQ_RX_DONE:
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

                            # Trigger RX LED
                            self._gpio_manager.blink_led(self.rxled_pin)

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
                        elif irqStat & self.lora.IRQ_TIMEOUT:
                            logger.warning("[RX] RX timeout detected")
                        elif irqStat & self.lora.IRQ_PREAMBLE_DETECTED:
                            pass
                        elif irqStat & self.lora.IRQ_SYNC_WORD_VALID:
                            pass  # Sync word valid - receiving packet data...
                        elif irqStat & self.lora.IRQ_HEADER_VALID:
                            pass  # Header valid - packet header received, payload coming...
                        elif irqStat & self.lora.IRQ_HEADER_ERR:
                            pass  # Header error - corrupted header, packet dropped
                        else:
                            pass  # Other RX interrupt

                        # Always restore RX continuous mode after processing any interrupt
                        # This ensures the radio stays ready for the next packet
                        try:
                            self.lora.setRx(self.lora.RX_CONTINUOUS)
                            await asyncio.sleep(self.RADIO_TIMING_DELAY)
                        except Exception as e:
                            logger.debug(f"Failed to restore RX mode: {e}")
                    except Exception as e:
                        logger.error(f"[IRQ RX] Error processing received packet: {e}")
                    finally:
                        # Clear packet processing flag
                        self._is_receiving_packet = False

                except asyncio.TimeoutError:
                    # No RX event within timeout - normal operation
                    rx_check_count += 1

                    # Sample noise floor during quiet periods
                    self._sample_noise_floor()

                    # Log every 500 checks (roughly every 5 seconds) to show RX task is alive
                    if rx_check_count % 500 == 0:
                        logger.debug(
                            f"[RX Task] Status check #{rx_check_count}, "
                            f"noise_floor={self._noise_floor:.1f}dBm"
                        )

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
            self.lora = SX126x()
            self.irq_pin = self._gpio_manager.setup_interrupt_pin(
                self.irq_pin_number, pull_up=False, callback=self._handle_interrupt
            )

            if self.irq_pin is not None:
                self._interrupt_setup = True
            else:
                logger.error(f"Failed to setup interrupt pin {self.irq_pin_number}")
                raise RuntimeError(f"Could not setup IRQ pin {self.irq_pin_number}")

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
                    logger.debug(f"TXEN pin {self.txen_pin} configured")
                    self._txen_pin_setup = True
                else:
                    logger.warning(f"Could not setup TXEN pin {self.txen_pin}")

            # Setup RXEN pin if needed
            if self.rxen_pin != -1:
                if self._gpio_manager.setup_output_pin(self.rxen_pin, initial_value=False):
                    logger.debug(f"RXEN pin {self.rxen_pin} configured")
                else:
                    logger.warning(f"Could not setup RXEN pin {self.rxen_pin}")

            # Setup LED pins if specified
            if self.txled_pin != -1 and not self._txled_pin_setup:
                if self._gpio_manager.setup_output_pin(self.txled_pin, initial_value=False):
                    self._txled_pin_setup = True
                    logger.debug(f"TX LED pin {self.txled_pin} configured")
                else:
                    logger.warning(f"Could not setup TX LED pin {self.txled_pin}")

            if self.rxled_pin != -1 and not self._rxled_pin_setup:
                if self._gpio_manager.setup_output_pin(self.rxled_pin, initial_value=False):
                    self._rxled_pin_setup = True
                    logger.debug(f"RX LED pin {self.rxled_pin} configured")
                else:
                    logger.warning(f"Could not setup RX LED pin {self.rxled_pin}")

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

                # Use RadioLib-compatible PA configuration and optimized setTxPower
                # This automatically configures PA based on requested power level
                self.lora.setTxPower(self.tx_power, self.lora.TX_POWER_SX1262)

                # Configure RX interrupts (critical for RX functionality!)
                rx_mask = self._get_rx_irq_mask()
                self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
                self.lora.clearIrqStatus(0xFFFF)

            else:  # Use full initialization
                # Reset RF module and set to standby
                if not self._basic_radio_setup(use_busy_check=True):
                    return False
                self.lora._fixResistanceAntenna()
                # Configure TCXO, regulator, calibration and RF switch
                if self.use_dio3_tcxo:
                    # Map voltage to DIO3 constants following Meshtastic pattern
                    voltage_map = {
                        1.6: self.lora.DIO3_OUTPUT_1_6,
                        1.7: self.lora.DIO3_OUTPUT_1_7,
                        1.8: self.lora.DIO3_OUTPUT_1_8,
                        2.2: self.lora.DIO3_OUTPUT_2_2,
                        2.4: self.lora.DIO3_OUTPUT_2_4,
                        2.7: self.lora.DIO3_OUTPUT_2_7,
                        3.0: self.lora.DIO3_OUTPUT_3_0,
                        3.3: self.lora.DIO3_OUTPUT_3_3,
                    }

                    voltage_constant = voltage_map.get(self.dio3_tcxo_voltage)
                    if voltage_constant is None:
                        closest_voltage = min(
                            voltage_map.keys(), key=lambda x: abs(x - self.dio3_tcxo_voltage)
                        )
                        voltage_constant = voltage_map[closest_voltage]
                        logger.debug(
                            f"DIO3 TCXO voltage {self.dio3_tcxo_voltage}V "
                            f"mapped to closest {closest_voltage}V"
                        )
                    else:
                        logger.debug(f"DIO3 TCXO voltage {self.dio3_tcxo_voltage}V mapped exactly")

                    # Set TCXO with 5ms delay (standard value)
                    self.lora.setDio3TcxoCtrl(voltage_constant, self.lora.TCXO_DELAY_5)
                    logger.info(f"DIO3 TCXO enabled: {self.dio3_tcxo_voltage}V, 5ms delay")
                    time.sleep(0.05)  # Allow TCXO to stabilize
                else:
                    logger.debug("DIO3 TCXO is not enabled")

                self.lora.setRegulatorMode(self.lora.REGULATOR_DC_DC)
                self.lora.calibrate(0x7F)
                self.lora.setDio2RfSwitch(False)

                # Set packet type and frequency
                rfFreq = int(self.frequency * 33554432 / 32000000)
                self.lora.setRfFrequency(rfFreq)

                # Set RX gain and TX power
                self.lora.writeRegister(self.lora.REG_RX_GAIN, [self.lora.RX_GAIN_POWER_SAVING], 1)
                # Use setTxPower for automatic PA configuration based on power level
                # For E22 modules: 22 dBm from SX1262 → ~30 dBm (1W) via external YP2233W PA
                logger.info(f"Setting TX power to {self.tx_power} dBm during initialization")
                self.lora.setTxPower(self.tx_power, self.lora.TX_POWER_SX1262)

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
                # Configure RX gain for maximum sensitivity (boosted mode)
                self.lora.setRxGain(self.lora.RX_GAIN_BOOSTED)

            # Program custom CAD thresholds to chip hardware if available
            if self._custom_cad_peak is not None and self._custom_cad_min is not None:
                logger.info(
                    f"Setting CAD thresholds to chip: peak={self._custom_cad_peak},",
                    f"min={self._custom_cad_min}",
                )
                try:
                    self.lora.setCadParams(
                        self.lora.CAD_ON_2_SYMB,  # 2 symbols for detection
                        self._custom_cad_peak,
                        self._custom_cad_min,
                        self.lora.CAD_EXIT_STDBY,  # exit to standby
                        0,  # no timeout
                    )
                    logger.debug("Custom CAD thresholds written")
                except Exception as e:
                    logger.warning(f"Failed to write CAD thresholds: {e}")

            # Set to RX continuous mode for initial operation
            self.lora.setRx(self.lora.RX_CONTINUOUS)

            self._initialized = True
            logger.info("SX1262 radio initialized successfully")

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
        """Calculate transmission timeout using C++ MeshCore formula"""

        symbol_time = float(1 << self.spreading_factor) / float(self.bandwidth)
        preamble_time = (self.preamble_length + 4.25) * symbol_time
        tmp = (8 * packet_length) - (4 * self.spreading_factor) + 28 + 16
        # CRC is enabled
        tmp -= 16

        if tmp > 0:
            payload_symbols = 8.0 + math.ceil(float(tmp) / float(4 * self.spreading_factor)) * (
                self.coding_rate + 4
            )
        else:
            payload_symbols = 8.0

        payload_time = payload_symbols * symbol_time
        air_time_ms = (preamble_time + payload_time) * 1000.0
        timeout_ms = math.ceil(air_time_ms) + 1000
        driver_timeout = timeout_ms * 64

        logger.debug(
            f"TX timing SF{self.spreading_factor}/{self.bandwidth/1000:.1f}kHz "
            f"CR4/{self.coding_rate} {packet_length}B: "
            f"symbol={symbol_time*1000:.1f}ms, "
            f"preamble={preamble_time*1000:.0f}ms, "
            f"tmp={tmp}, "
            f"payload_syms={payload_symbols:.1f}, "
            f"payload={payload_time*1000:.0f}ms, "
            f"air_time={air_time_ms:.0f}ms, "
            f"timeout={timeout_ms}ms, "
            f"driver_timeout={driver_timeout}"
        )

        return timeout_ms, driver_timeout

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
        """Configure interrupts for transmission - TX and CAD only, disable RX interrupts"""
        # Set up TX and CAD interrupts only - this prevents spurious RX interrupts during TX
        mask = self._get_tx_irq_mask() | self.lora.IRQ_CAD_DONE | self.lora.IRQ_CAD_DETECTED
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
                await asyncio.sleep(self.RADIO_TIMING_DELAY)
                busy_wait += 1

        # Listen Before Talk (LBT) - Check for channel activity using CAD
        lbt_attempts = 0
        max_lbt_attempts = 5
        while lbt_attempts < max_lbt_attempts:
            try:
                # Perform CAD with your custom thresholds
                channel_busy = await self.perform_cad(timeout=0.5)
                if not channel_busy:
                    logger.debug(f"Channel clear after {lbt_attempts + 1} CAD checks")
                    break
                else:
                    lbt_attempts += 1
                    if lbt_attempts < max_lbt_attempts:
                        # Jitter (50-200ms)
                        base_delay = random.randint(50, 200)
                        # Exponential backoff: base * 2^attempts
                        backoff_ms = base_delay * (2 ** (lbt_attempts - 1))
                        # Cap at 5 seconds maximum
                        backoff_ms = min(backoff_ms, 5000)

                        logger.debug(
                            f"Channel busy (CAD detected activity), backing off {backoff_ms}ms "
                            f"- attempt {lbt_attempts}/{max_lbt_attempts} (exponential backoff)"
                        )
                        await asyncio.sleep(backoff_ms / 1000.0)
                    else:
                        logger.warning(
                            f"Channel still busy after {max_lbt_attempts} CAD attempts - tx anyway"
                        )
            except Exception as e:
                logger.debug(f"CAD check failed: {e}, proceeding with transmission")
                break

        # Set TXEN/RXEN pins for TX mode (matching RadioLib timing)
        self._control_tx_rx_pins(tx_mode=True)

        # Check busy status before starting transmission
        if self.lora.busyCheck():
            logger.warning("Radio is busy before starting transmission")
            # Wait for radio to become ready
            busy_timeout = 0
            while self.lora.busyCheck() and busy_timeout < 100:
                await asyncio.sleep(self.RADIO_TIMING_DELAY)
                busy_timeout += 1
            if self.lora.busyCheck():
                logger.error("Radio stayed busy - cannot start transmission")
                return False

        return True

    def _control_tx_rx_pins(self, tx_mode: bool) -> None:
        """Control TXEN/RXEN pins for the E22 module (simple and deterministic)."""

        # TX: TXEN=HIGH, RXEN=LOW
        if tx_mode:
            if self.txen_pin != -1:
                self._gpio_manager.set_pin_high(self.txen_pin)
            if self.rxen_pin != -1:
                self._gpio_manager.set_pin_low(self.rxen_pin)

        # RX or idle: TXEN=LOW, RXEN=HIGH
        else:
            if self.txen_pin != -1:
                self._gpio_manager.set_pin_low(self.txen_pin)
            if self.rxen_pin != -1:
                self._gpio_manager.set_pin_high(self.rxen_pin)

    async def _execute_transmission(self, driver_timeout: int) -> bool:
        """Execute the actual transmission. Returns True if successful."""
        # Start transmission
        self.lora.setTx(driver_timeout)

        # Check if radio accepted the TX command (wait for busy to clear)
        busy_timeout = 0
        while self.lora.busyCheck() and busy_timeout < 50:  # 500ms max wait
            await asyncio.sleep(self.RADIO_TIMING_DELAY)
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
            # No warning for 0x0000 - interrupt already cleared by handler
            pass

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
        logger.debug("[TX->RX] Starting RX mode restoration after transmission")
        try:
            if self.lora:
                # Clear any interrupt flags and set standby
                self.lora.clearIrqStatus(0xFFFF)
                self.lora.setStandby(self.lora.STANDBY_RC)

                # Brief delay for radio to settle
                await asyncio.sleep(0.05)

                # Configure full RX interrupts and set RX continuous mode
                rx_mask = (
                    self._get_rx_irq_mask() | self.lora.IRQ_CAD_DONE | self.lora.IRQ_CAD_DETECTED
                )
                self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
                self.lora.setRx(self.lora.RX_CONTINUOUS)

                # Final clear of any spurious flags and we're done
                await asyncio.sleep(0.05)
                self.lora.clearIrqStatus(0xFFFF)

                logger.debug("[TX->RX] RX mode restoration completed")

        except Exception as e:
            logger.warning(f"[TX->RX] Failed to restore RX mode after TX: {e}")

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

                logger.debug(
                    f"Setting TX timeout: {final_timeout_ms}ms "
                    f"(tOut={driver_timeout}) for {length} bytes"
                )

                if not await self._prepare_radio_for_tx():
                    return

                # Setup TX interrupts AFTER CAD checks (CAD changes interrupt config)
                self._setup_tx_interrupts()
                await asyncio.sleep(self.RADIO_TIMING_DELAY)

                # Ensure PA configuration is correct before transmission
                # Re-apply power settings to guarantee proper external
                # PA operation think cad might be reseting
                logger.debug(f"Re-applying TX power {self.tx_power} dBm before transmission")
                self.lora.setTxPower(self.tx_power, self.lora.TX_POWER_SX1262)

                # Execute the transmission
                if not await self._execute_transmission(driver_timeout):
                    return

                # Wait for transmission to complete
                if not await self._wait_for_transmission_complete(timeout_seconds):
                    return

                # Finalize transmission and log results
                self._finalize_transmission()

                # Trigger TX LED
                self._gpio_manager.blink_led(self.txled_pin)

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

    def _sample_noise_floor(self) -> None:
        """Sample noise floor"""
        if not self._initialized or self.lora is None:
            return

        # Don't sample during TX operations or if recently received packet
        if self._tx_lock.locked():
            return

        # Give 500ms quiet time after any packet activity
        if time.time() - self._last_packet_activity < 0.5:
            return

        # Don't sample if currently receiving a packet
        if self._is_receiving_packet:
            return

        # Sample RSSI during quiet periods only
        if self._num_floor_samples < self.NUM_NOISE_FLOOR_SAMPLES:
            try:
                raw_rssi = self.lora.getRssiInst()
                if raw_rssi is not None:
                    current_rssi = -(float(raw_rssi) / 2)

                    # This prevents packet RSSI from contaminating noise floor measurements
                    if current_rssi < (self._noise_floor + self.SAMPLING_THRESHOLD):
                        self._num_floor_samples += 1
                        self._floor_sample_sum += current_rssi

            except Exception as e:
                logger.debug(f"Failed to sample noise floor: {e}")

        elif (
            self._num_floor_samples >= self.NUM_NOISE_FLOOR_SAMPLES and self._floor_sample_sum != 0
        ):
            # Calculate new noise floor average
            new_noise_floor = self._floor_sample_sum / self.NUM_NOISE_FLOOR_SAMPLES

            # Clamp to reasonable bounds (-150 to -50 dBm)
            if new_noise_floor < -150:
                new_noise_floor = -150
            elif new_noise_floor > -50:
                new_noise_floor = -50

            self._noise_floor = new_noise_floor
            self._floor_sample_sum = 0.0
            self._num_floor_samples = 0

    def get_noise_floor(self) -> Optional[float]:
        """
        Get current noise floor in dBm.
        Returns properly sampled noise floor from background measurements.
        """
        if not self._initialized or self.lora is None:
            return 0.0

        # If currently transmitting, return 0 (clear indicator)
        if hasattr(self, "_tx_lock") and self._tx_lock.locked():
            return 0.0

        # Return the properly sampled and averaged noise floor
        return self._noise_floor

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

    def set_custom_cad_thresholds(self, peak: int, min_val: int) -> None:
        """Set custom CAD thresholds that override the defaults.

        Args:
            peak: CAD detection peak threshold (0-31)
            min_val: CAD detection minimum threshold (0-31)
        """
        if not (0 <= peak <= 31) or not (0 <= min_val <= 31):
            raise ValueError("CAD thresholds must be between 0 and 31")

        self._custom_cad_peak = peak
        self._custom_cad_min = min_val
        logger.info(f"Custom CAD thresholds set: peak={peak}, min={min_val}")

    def clear_custom_cad_thresholds(self) -> None:
        """Clear custom CAD thresholds and revert to defaults."""
        self._custom_cad_peak = None
        self._custom_cad_min = None
        logger.info("Custom CAD thresholds cleared, reverting to defaults")

    def _get_thresholds_for_current_settings(self) -> tuple[int, int]:
        """Fetch CAD thresholds for the current spreading factor.
        Returns (cadDetPeak, cadDetMin).
        """
        # Use custom thresholds if set
        if self._custom_cad_peak is not None and self._custom_cad_min is not None:
            return (self._custom_cad_peak, self._custom_cad_min)

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
        If calibration=True, uses provided thresholds and returns info.
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
            # Put radio in standby mode before CAD configuration
            self.lora.setStandby(self.lora.STANDBY_RC)

            # Clear any existing interrupt flags
            existing_irq = self.lora.getIrqStatus()
            if existing_irq != 0:
                self.lora.clearIrqStatus(existing_irq)

            # Configure CAD interrupts
            cad_mask = self.lora.IRQ_CAD_DONE | self.lora.IRQ_CAD_DETECTED
            self.lora.setDioIrqParams(cad_mask, cad_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)

            self.lora.setCadParams(
                self.lora.CAD_ON_2_SYMB,  # 2 symbols
                det_peak,
                det_min,
                self.lora.CAD_EXIT_STDBY,  # exit to standby
                0,  # no timeout
            )

            # Clear CAD event before starting
            self._cad_event.clear()

            # Start CAD operation
            self.lora.setCad()

            logger.debug(f"CAD started with peak={det_peak}, min={det_min}")

            # Wait for CAD completion
            try:
                await asyncio.wait_for(self._cad_event.wait(), timeout=timeout)
                self._cad_event.clear()

                irq = self.lora.getIrqStatus()
                logger.debug(f"CAD completed with IRQ status: 0x{irq:04X}")
                self.lora.clearIrqStatus(irq)
                detected = bool(irq & self.lora.IRQ_CAD_DETECTED)
                cad_done = bool(irq & self.lora.IRQ_CAD_DONE)

                if calibration:
                    return {
                        "sf": self.spreading_factor,
                        "bw": self.bandwidth,
                        "det_peak": det_peak,
                        "det_min": det_min,
                        "detected": detected,
                        "cad_done": cad_done,
                        "timestamp": time.time(),
                        "irq_status": irq,
                    }
                else:
                    return detected

            except asyncio.TimeoutError:
                logger.debug("CAD operation timed out")
                # Check if there were any interrupt flags set anyway
                irq = self.lora.getIrqStatus()
                if irq != 0:
                    logger.debug(f"CAD timeout but IRQ status: 0x{irq:04X}")
                    self.lora.clearIrqStatus(irq)

                if calibration:
                    return {
                        "sf": self.spreading_factor,
                        "bw": self.bandwidth,
                        "det_peak": det_peak,
                        "det_min": det_min,
                        "detected": False,
                        "timestamp": time.time(),
                        "timeout": True,
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
                    "error": str(e),
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
