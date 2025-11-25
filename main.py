import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SimulatedNetwork:
    def __init__(self, packet_size_limit=64, delay=0.1):
        self.packet_size_limit = packet_size_limit
        self.delay = delay

    def send(self, sender_name, data, description=""):
        print(f"\n--- {sender_name} відправляє: {description} ({len(data)} байт) ---")
        for i in range(0, len(data), self.packet_size_limit):
            chunk = data[i:i + self.packet_size_limit]
            print(f"  [Пакет] -> {chunk.hex()[:20]}..." if len(chunk) > 10 else f"  [Пакет] -> {chunk.hex()}")
            time.sleep(self.delay)

        return data