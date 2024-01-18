import sctp
from threading import Thread
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
from random import randint
import socket

def handle_connection(bob_socket, shared_secret_bob):
    # Derive AES key
    shared_secret_bytes_bob = shared_secret_bob.to_bytes((shared_secret_bob.bit_length() + 7) // 8, byteorder='big')
    aes_key_bob = derive_aes_key(shared_secret_bytes_bob)

    while True:
        # Receive and decrypt a message from Alice
        encrypted_message = bob_socket.recv(1024)
        if not encrypted_message:
            break
        decrypted_message = decrypt(encrypted_message, aes_key_bob)
        print(f"Received Message from Alice: {decrypted_message.decode('utf-8', 'replace')}")

def derive_aes_key(shared_secret):
    # Use PBKDF2 to derive a key from the shared secret
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(shared_secret)
    return key

def decrypt(ciphertext, key):
    # Separate IV and ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Use AES-256 decryption
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(ciphertext) + decryptor.finalize()
    return message


def encrypt(message, key):
    # Use AES-256 encryption
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext


def generate_key_exchange():
    p = 23
    g = 5

    # Private keys for each party
    alice_private_key = randint(1, p-1)
    bob_private_key = randint(1, p-1)

    # Generate public keys
    alice_public_key = pow(g, alice_private_key, p)
    bob_public_key = pow(g, bob_private_key, p)

    # Calculate shared secret
    shared_secret_alice = pow(bob_public_key, alice_private_key, p)
    shared_secret_bob = pow(alice_public_key, bob_private_key, p)

    return shared_secret_alice, shared_secret_bob


def main():
    # Establish a SCTP socket connection to Alice
    bob_socket = sctp.sctpsocket_tcp(socket.AF_INET)
    bob_socket.connect(('localhost', 12345))
    print("Connected to Alice!")

    # Receive Alice's public key
    shared_secret_alice = int(bob_socket.recv(1024).decode())

    while True:
        # Generate and exchange keys
        shared_secret_alice, shared_secret_bob = generate_key_exchange()

        # Send public key to Alice
        bob_socket.send(str(shared_secret_bob).encode())

        # Create a thread to handle the connection
        connection_thread = Thread(target=handle_connection, args=(bob_socket, shared_secret_bob))
        connection_thread.start()

        # Derive AES key
        shared_secret_bytes_bob = shared_secret_bob.to_bytes((shared_secret_bob.bit_length() + 7) // 8, byteorder='big')
        aes_key_bob = derive_aes_key(shared_secret_bytes_bob)

        # Encrypt and send a message to Alice
        message = b"Hello, Alice! This is a secret message."
        encrypted_message = encrypt(message, aes_key_bob)
        bob_socket.send(encrypted_message)

if __name__ == "__main__":
    main()
