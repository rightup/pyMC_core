class BaseLoRa:
    def begin(self):
        raise NotImplementedError

    def end(self):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError

    def beginPacket(self):
        raise NotImplementedError

    def endPacket(self, timeout: int) -> bool:
        raise NotImplementedError

    def write(self, data, length: int):
        raise NotImplementedError

    def request(self, timeout: int) -> bool:
        raise NotImplementedError

    def available(self):
        raise NotImplementedError

    def read(self, length: int):
        raise NotImplementedError

    def wait(self, timeout: int) -> bool:
        raise NotImplementedError

    def status(self):
        raise NotImplementedError
