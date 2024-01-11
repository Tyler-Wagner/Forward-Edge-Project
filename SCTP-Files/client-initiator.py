import sctp
import socket
import os
import random
import string
import time

def generate_random_text_file(filename, size):
    with open(filename, 'w') as file:
        file.write(''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size)))

def encrypt_file(input_filename, output_filename):
    # Example: ROT13 encryption
    with open(input_filename, 'r') as infile:
        content = infile.read()
        encrypted_content = content.encode('rot_13')

    with open(output_filename, 'wb') as outfile:
        outfile.write(encrypted_content)

def send_sctp_file(server_ip, server_port, filename):
    # Create a new SCTP socket
    sock = sctp.sctpsocket_tcp(socket.AF_INET)

    # Connect to the server
    sock.connect((server_ip, server_port))

    # Read the file content
    with open(filename, 'rb') as file:
        file_content = file.read()

    # Send the encrypted file
    sock.sctp_send(file_content)

    print(f"Sent file: {filename}")

    # Receive the response
    response = sock.sctp_recv(1024)
    print(f"Response from server: {response.decode('utf-8')}")

    # Close the socket
    sock.close()

def main():
    # Generate a random text file
    filename = "file_to_send.txt"
    generate_random_text_file(filename, 100)
    encrypt_file(filename, "encrypted_file_to_send.txt")

    # Update these values with your server details
    server_ip = "192.168.1.100"  # Replace with the actual IP address of the server
    server_port = 12345

    try:
        while True:
            # Send the encrypted file
            send_sctp_file(server_ip, server_port, "encrypted_file_to_send.txt")

            # Wait for 3 minutes
            time.sleep(180)

    except KeyboardInterrupt:
        print("Program stopped by user.")

if __name__ == "__main__":
    main()
