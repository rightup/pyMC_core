<!-- PROJECT SHIELDS -->
[![PyPI - Downloads](https://img.shields.io/pypi/dm/LoRaRF)](https://pypi.org/project/LoRaRF/)
[![PyPI](https://img.shields.io/pypi/v/LoRaRF)](https://pypi.org/project/LoRaRF/)
[![GitHub license](https://img.shields.io/github/license/chandrawi/LoRaRF-Python)](https://github.com/chandrawi/LoRaRF-Python/blob/main/LICENSE)

# LoRa-RF Python Library

LoRa-RF Python is a library for basic transmitting and receiving data using LoRa module with Semtech SX126x series, SX127x series, or LLCC68. The library works by interfacing SPI port and some GPIO pins under linux kernel. Support configuring frequency, modulation parameter, transmit power, receive gain and other RF parameters on both LoRa and FSK modulation also support handling transmit and receive using interrupt signal.

This readme is written for quick start guide. Visit this [link](https://github.com/chandrawi/LoRaRF-Python/wiki) for complete documentation.

## Hardware Compatibility

Theoritically all LoRa modules using SX126x series (SX1261, SX1262, SX1268), SX127x series (SX1272, SX1276, SX1277, SX1278, SX1279), or LLCC68 will compatible using this library. Some LoRa module which already tested and confirmed compatible are:
* Ebyte: E22-400M22S, E22-900M22S, E22-400M30S, E22-900M30S

Currently only Raspberry pi zero, zero W, 3A, 3B, 3B+, 4A, and 4B supported as host controller. Support for other single board computer will be added in the future. The Linux distro already tested using this library are:
* Raspberry pi OS
* Ubuntu Core 32-bit

In order to connect to a LoRa module, SPI port must be enabled. For Raspberry pi OS, this is done by set SPI interface enable using raspi-config or edit `/boot/config.txt` by adding following line.
```txt
dtparam=spi=on
```

## Installation

### Using pip

Using terminal run following command.
```sh
pip3 install LoRaRF
```

### Using Git and Build Package

To using latest update of the library, you can clone then build python package manually. Using this method require setuptools and wheel module.
```sh
git clone https://github.com/chandrawi/LoRaRF-Python.git
cd LoRaRF-Python
python3 setup.py bdist_wheel
pip3 install dist/LoRaRF-1.3.0-py3-none-any.whl
```

## Initialization

To work with the library, first you must import `SX126x` or `SX127x` python module depending LoRa module you use. Then initialize the module by creating an object.

```python
# for SX126x series or LLCC68
from LoRaRF import SX126x
LoRa = SX126x()

# for SX127x series
from LoRaRF import SX127x
LoRa = SX127x()
```

Before calling any configuration methods, doing transmit or receive operation you must call `begin()` method.

```python
LoRa.begin()
```

## Hardware Configuration

### Wiring Connections

Power pins, SPI pins, `RESET`, and `BUSY` pins must be connected between host controller and LoRa module. If you want to use interrupt operation, you can connect one of `DIO1`, `DIO2`, or `DIO3` pin. You also should connect `TXEN` and `RXEN` pins if your LoRa module have those pins.

The default SPI port is using bus id 0 and cs id 0. The default GPIO pins used for connecting to SX126x and SX127x with Broadcom pin numbering are as follows.

| Semtech SX126x | Semtech SX127x | Raspberry Pi |
| :------------: | :-------------:| :-----------:|
| VCC | VCC | 3.3V |
| GND | GND | GND |
| SCK | SCK | GPIO 11 |
| MISO | MISO | GPIO 9 |
| MOSI | MOSI | GPIO 10 |
| NSS | NSS | GPIO 8 |
| RESET | RESET | GPIO 22 |
| BUSY | | GPIO 23|
| DIO1 | DIO1 | -1 (unused) |
| TXEN | TXEN | -1 (unused) |
| RXEN | RXEN | -1 (unused) |

### SPI Port Configuration

To configure SPI port or SPI frequency call `setSPI()` method before `begin()` method.
```python
# set to use SPI with bus id 0 and cs id 1 and speed 7.8 Mhz
LoRa.setSPI(0, 0, 7800000)
LoRa.begin()
```

### I/O Pins Configuration

To configure I/O pins (NSS, RESET, BUSY, IRQ, TXEN, RXEN pin) call `setPins()` before `begin()` method.
```python
# set RESET->22, BUSY->23, DIO1->26, TXEN->5, RXEN->25
LoRa.setPins(22, 23, 26, 5, 25)
LoRa.begin()
```

## Modem Configuration

Before transmit or receive operation you can configure transmit power and receive gain or matching frequency, modulation parameter, packet parameter, and synchronize word with other LoRa device you want communicate.

### Transmit Power

```python
# set transmit power to +22 dBm for SX1262
LoRa.setTxPower(22, LoRa.TX_POWER_SX1262)
```

### Receive Gain

```python
# set receive gain to power saving
LoRa.setRxGain(LoRa.RX_GAIN_POWER_SAVING)
```

### Frequency

```python
# Set frequency to 915 Mhz
LoRa.setFrequency(915000000)
```

### Modulation Parameter

```python
# set spreading factor 8, bandwidth 125 kHz, coding rate 4/5, and low data rate optimization off
LoRa.setLoRaModulation(8, 125000, 5, False)
```

### Packet Parameter

```python
# set explicit header mode, preamble length 12, payload length 15, CRC on and no invert IQ operation
LoRa.setLoRaPacket(LoRa.HEADER_EXPLICIT, 12, 15, true, False)
```

### Synchronize Word

```python
# Set syncronize word for public network (0x3444)
LoRa.setSyncWord(0x3444)
```

## Transmit Operation

Transmit operation begin with calling `beginPacket()` method following by `write()` method to write package to be tansmitted and ended with calling `endPacket()` method. For example, to transmit "HeLoRa World!" message and an increment counter you can use following code.

```python
# message and counter to transmit
message = "HeLoRa World!\0"
messageList = list(message)
for i in range(len(messageList)) : messageList[i] = ord(messageList[i])
counter = 0

LoRa.beginPacket()
LoRa.write(message, sizeof(message)) # write multiple bytes
LoRa.write(counter)                  # write single byte
LoRa.endPacket()
LoRa.wait()
counter += 1
```

For more detail about transmit operation, please visit this [link](https://github.com/chandrawi/LoRaRF-Python/wiki/Transmit-Operation).

## Receive Operation

Receive operation begin with calling `request()` method following by `read()` method to read received package. `available()` method can be used to get length of remaining package. For example, to receive message and a counter in last byte you can use following code.

```python
LoRa.request()
LoRa.wait()

# get message and counter in last byte
message = ""
while LoRa.available() > 1 :
  message += chr(LoRa.read())        # read multiple bytes
counter = LoRa.read()                # read single byte
```

For more detail about receive operation, please visit this [link](https://github.com/chandrawi/LoRaRF-Python/wiki/Receive-Operation).

## Examples

See examples for [SX126x](https://github.com/chandrawi/LoRaRF-Python/tree/main/examples/SX126x), [SX127x](https://github.com/chandrawi/LoRaRF-Python/tree/main/examples/SX127x) and [simple network implementation](https://github.com/chandrawi/LoRaRF-Python/tree/main/examples/network).

## Contributor

[Chandra Wijaya Sentosa](https://github.com/chandrawi) <<chandra.w.sentosa@gmail.com>>

### Upcoming features...
Base class will allow for python3-libgpiod package
