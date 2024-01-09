import socket
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import random
import string
import time

def derive_key(password: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b"",  # No salt
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

def encrypt_message(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

password = b"your_secret_password"
key = derive_key(password)

iv = os.urandom(16)

while True:
    message = ''.join(random.choice(string.ascii_letters) for _ in range(10))
    encrypted_message = encrypt_message(key, iv, message.encode('utf-8'))
    client_socket.send(encrypted_message)

    print(f"Sent: {message}")

    time.sleep(1)
