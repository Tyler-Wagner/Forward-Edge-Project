import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import random
import time

def encrypt_message(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

while True:
    message = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(10))
    key = os.urandom(32)
    iv = os.urandom(16)

    encrypted_message = encrypt_message(key, iv, message.encode('utf-8'))
    client_socket.send(encrypted_message)

    print(f"Sent: {message}")

    time.sleep(1)
