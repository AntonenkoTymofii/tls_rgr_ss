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

class Server:
    def __init__(self):
        print("Server: Генерація RSA ключів...")
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self._private_key.public_key()
        self.server_random = None
        self.client_random = None
        self.session_key = None

    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def process_premaster(self, encrypted_premaster):
        try:
            premaster = self._private_key.decrypt(
                encrypted_premaster,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return premaster
        except Exception as e:
            print(f"Server Error: Decryption failed - {e}")
            return None

    def generate_session_key(self, premaster, client_random):
        self.client_random = client_random
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'tls handshake',
        )
        material = premaster + self.client_random + self.server_random
        self.session_key = hkdf.derive(material)
        print(f"Server: Сеансовий ключ згенеровано: {self.session_key.hex()[:10]}...")

    def decrypt_message(self, encrypted_data):
        if not self.session_key:
            raise Exception("Session key not established")
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(self.session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def encrypt_message(self, plaintext):
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

class Client:
    def __init__(self):
        self.client_random = None
        self.server_random = None
        self.session_key = None

    def encrypt_premaster(self, public_key_bytes, premaster):
        server_pub_key = serialization.load_pem_public_key(public_key_bytes)
        encrypted = server_pub_key.encrypt(
            premaster,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def generate_session_key(self, premaster, server_random):
        self.server_random = server_random
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'tls handshake',
        )
        material = premaster + self.client_random + self.server_random
        self.session_key = hkdf.derive(material)
        print(f"Client: Сеансовий ключ згенеровано: {self.session_key.hex()[:10]}...")

    def encrypt_message(self, plaintext):
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_message(self, encrypted_data):
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(self.session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)


def run_tls_simulation():
    print("=== ПОЧАТОК СИМУЛЯЦІЇ TLS HANDSHAKE ===\n")

    network = SimulatedNetwork(packet_size_limit=50, delay=0.05)
    client = Client()
    server = Server()

    client.client_random = os.urandom(32)
    msg_client_hello = b"ClientHello" + client.client_random
    received_hello = network.send("Client", msg_client_hello, "Client Hello + Random")

    server.server_random = os.urandom(32)
    server_pub_key_bytes = server.get_public_key_bytes()
    msg_server_hello = b"ServerHello" + server.server_random + server_pub_key_bytes
    received_server_resp = network.send("Server", msg_server_hello, "Server Hello + Key")

    server_rand_from_msg = received_server_resp[11:43]
    pub_key_from_msg = received_server_resp[43:]

    premaster_secret = os.urandom(32)
    encrypted_premaster = client.encrypt_premaster(pub_key_from_msg, premaster_secret)
    rec_enc_premaster = network.send("Client", encrypted_premaster, "Encrypted Premaster")

    decrypted_premaster = server.process_premaster(rec_enc_premaster)

    print("\n--- Генерація сеансових ключів ---")
    client.generate_session_key(premaster_secret, server_rand_from_msg)
    server.generate_session_key(decrypted_premaster, client.client_random)

    client_ready_msg = client.encrypt_message(b"Client Ready")
    rec_client_ready = network.send("Client", client_ready_msg, "Encrypted 'Client Ready'")
    server.decrypt_message(rec_client_ready)

    server_ready_msg = server.encrypt_message(b"Server Ready")
    rec_server_ready = network.send("Server", server_ready_msg, "Encrypted 'Server Ready'")
    client.decrypt_message(rec_server_ready)

    print("\n=== HANDSHAKE ЗАВЕРШЕНО. ПЕРЕДАЧА ДАНИХ ===\n")
    secret_message = "Це секретне повідомлення для РГР. Шифрування AES-GCM.".encode('utf-8')
    encrypted_chat_msg = client.encrypt_message(secret_message)
    rec_chat_msg = network.send("Client", encrypted_chat_msg, "DATA MESSAGE")

    decrypted_chat_text = server.decrypt_message(rec_chat_msg).decode('utf-8')
    print(f"\nServer Received: {decrypted_chat_text}")


if __name__ == "__main__":
    run_tls_simulation()