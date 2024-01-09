import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def decrypt_message(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen(1)

print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

while True:
    client_socket, addr = server_socket.accept()
    print(f"Accepted connection from {addr}")

    key = os.urandom(32)  # 32 bytes for AES-256
    iv = os.urandom(16)   # 16 bytes for AES block size

    while True:
        encrypted_message = client_socket.recv(1024)
        if not encrypted_message:
            break

        decrypted_message = decrypt_message(key, iv, encrypted_message)
        print(f"Received: {decrypted_message}")

    client_socket.close()
