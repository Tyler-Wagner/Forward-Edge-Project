import sctp
import socket

def start_sctp_server(port):
    # Create a new SCTP socket
    sock = sctp.sctpsocket_tcp(socket.AF_INET)

    # Bind to all available network interfaces
    sock.bind(('0.0.0.0', port))

    # Listen for incoming connections
    sock.listen()

    print(f"Server listening on 0.0.0.0:{port}")

    while True:
        # Accept a connection
        client_sock, client_addr = sock.accept()
        print(f"Accepted connection from {client_addr}")

        # Receive the file content from the client
        file_content = client_sock.sctp_recv(1024)

        # Decrypt the content (using ROT13 in this example)
        decrypted_content = file_content.decode('rot_13')

        # Save the decrypted content to a file
        with open(f"received_file.txt", 'w') as file:
            file.write(decrypted_content)

        print(f"File received and saved.")

        # Send a response back to the client
        response = b"File received successfully!"
        client_sock.sctp_send(response)

        # Close the client socket
        client_sock.close()

if __name__ == "__main__":
    server_port = 12345

    start_sctp_server(server_port)
