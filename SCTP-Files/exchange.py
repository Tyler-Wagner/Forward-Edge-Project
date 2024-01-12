from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import socket
import time
from threading import Timer

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_public_key(data, public_key):
    key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_key = cipher_rsa.encrypt(key)

    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return encrypted_key, cipher_aes.nonce, tag, ciphertext

def decrypt_with_private_key(encrypted_key, nonce, tag, ciphertext, private_key):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    key = cipher_rsa.decrypt(encrypted_key)

    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext

def key_exchange_init(sock, public_key_recv):
    private_key_init, public_key_init = generate_key_pair()
    sock.send(public_key_init)

    # Receive encrypted key from recv
    encrypted_key_recv = sock.recv(1024)
    nonce_recv = sock.recv(16)
    tag_recv = sock.recv(16)
    ciphertext_recv = sock.recv(1024)

    # Decrypt the key received from recv
    key_recv = decrypt_with_private_key(encrypted_key_recv, nonce_recv, tag_recv, ciphertext_recv, private_key_init)
    print("Key received from recv:", key_recv.decode())

    # Encrypt and send a key to recv
    data = b"Hello from init!"
    encrypted_key_init, nonce_init, tag_init, ciphertext_init = encrypt_with_public_key(data, public_key_recv)
    sock.send(encrypted_key_init)
    sock.send(nonce_init)
    sock.send(tag_init)
    sock.send(ciphertext_init)

def key_exchange_recv(sock, public_key_init):
    # Receive public key from init
    public_key_recv = sock.recv(1024)

    # Send encrypted key to init
    private_key_recv, public_key_recv = generate_key_pair()
    data = b"Hello from recv!"
    encrypted_key_recv, nonce_recv, tag_recv, ciphertext_recv = encrypt_with_public_key(data, public_key_init)
    sock.send(encrypted_key_recv)
    sock.send(nonce_recv)
    sock.send(tag_recv)
    sock.send(ciphertext_recv)

    # Decrypt the key received from init
    encrypted_key_init = sock.recv(1024)
    nonce_init = sock.recv(16)
    tag_init = sock.recv(16)
    ciphertext_init = sock.recv(1024)
    key_init = decrypt_with_private_key(encrypted_key_init, nonce_init, tag_init, ciphertext_init, private_key_recv)
    print("Key received from init:", key_init.decode())

def key_exchange_timer(sock, public_key_recv, public_key_init):
    key_exchange_init(sock, public_key_recv)
    time.sleep(3 * 60)  # 3 minutes sleep
    key_exchange_recv(sock, public_key_init)

if __name__ == "__main__":
    # Example socket communication (you may need to adjust the host and port)
    host = '127.0.0.1'
    port = 12345

    # Create socket for init
    sock_init = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_init.connect((host, port))

    # Create socket for recv
    sock_recv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_recv.connect((host, port))

    # Generate key pairs for init and recv
    private_key_init, public_key_init = generate_key_pair()
    private_key_recv, public_key_recv = generate_key_pair()

    # Exchange keys initially
    key_exchange_init(sock_init, public_key_recv)
    key_exchange_recv(sock_recv, public_key_init)

    # Set up timer for periodic key exchange
    Timer(3 * 60, key_exchange_timer, [sock_init, public_key_recv, public_key_init]).start()

    # Continue with other communication or tasks
    # ...

    # Close sockets when done
    sock_init.close()
    sock_recv.close()
