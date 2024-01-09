import socket
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32,
    )
    key = kdf.derive(password)
    return key

def decrypt_message(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
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

    salt = os.urandom(16)
    password = b"your_secret_password"
    key = derive_key(password, salt)

    iv = os.urandom(16)

    while True:
        encrypted_message = client_socket.recv(1024)
        if not encrypted_message:
            break

        decrypted_message = decrypt_message(key, iv, encrypted_message)
        print(f"Received: {decrypted_message.decode('utf-8')}")

    client_socket.close()
