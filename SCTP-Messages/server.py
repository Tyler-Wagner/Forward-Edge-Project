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

        # Receive the message from the client
        message = client_sock.sctp_recv(1024)
        print(f"Received message: {message.decode('utf-8')}")

        # Send a response back to the client
        response = b"Message received successfully!"
        client_sock.sctp_send(response)

        # Close the client socket
        client_sock.close()

if __name__ == "__main__":
    server_port = 12345

    start_sctp_server(server_port)
