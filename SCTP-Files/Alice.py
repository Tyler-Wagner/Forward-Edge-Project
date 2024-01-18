import sctp
from threading import Thread
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
from random import randint
import time
import socket

def handle_connection(alice_socket, shared_secret_alice):
    # Derive AES key
    shared_secret_bytes_alice = shared_secret_alice.to_bytes((shared_secret_alice.bit_length() + 7) // 8, byteorder='big')
    aes_key_alice = derive_aes_key(shared_secret_bytes_alice)

    while True:
        # Receive and decrypt a message from Bob
        encrypted_message = alice_socket.recv(1024)
        if not encrypted_message:
            break
        decrypted_message = decrypt(encrypted_message, aes_key_alice)
        print(f"Received Message from Bob: {decrypted_message.decode('utf-8', 'replace')}")

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
    # Use AES-256 decryption
    iv = ciphertext[:16]
    print(ciphertext)
    print('iv d:', iv)
    ciphertext = ciphertext[15:]
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(ciphertext) + decryptor.finalize()
    return message

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

def encrypt(message, key):
    # Use AES-256 encryption
    iv = os.urandom(16)
    print('iv e:', iv)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return iv + ciphertext


def main():
    # Establish a SCTP socket connection
    alice_socket = sctp.sctpsocket_tcp(socket.AF_INET)
    alice_socket.bind(('localhost', 12345))
    alice_socket.listen()

    print("Waiting for Bob to connect...")
    bob_connection, bob_address = alice_socket.accept()
    print("Bob connected!")

    # Generate and exchange keys
    shared_secret_alice, shared_secret_bob = generate_key_exchange()

    # Send public key to Bob
    bob_connection.send(str(shared_secret_alice).encode())

    # Receive Bob's public key
    shared_secret_bob = int(bob_connection.recv(1024).decode())

    # Create a thread to handle the connection
    connection_thread = Thread(target=handle_connection, args=(bob_connection, shared_secret_alice))
    connection_thread.start()

    # Derive AES key
    shared_secret_bytes_alice = shared_secret_alice.to_bytes((shared_secret_alice.bit_length() + 7) // 8, byteorder='big')
    aes_key_alice = derive_aes_key(shared_secret_bytes_alice)

    while True:
        # Encrypt and send a new message to Bob
        message = b"Hello, Bob! This is a secret message."
        encrypted_message = encrypt(message, aes_key_alice)
        bob_connection.send(encrypted_message)
        time.sleep(2)  # Adjust the sleep duration as needed

if __name__ == "__main__":
    main()
