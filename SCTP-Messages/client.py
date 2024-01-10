import sctp
import socket

def send_sctp_packet(server_ip, server_port, message):
    # Create a new SCTP socket
    sock = sctp.sctpsocket_tcp(socket.AF_INET)

    # Connect to the server
    sock.connect((server_ip, server_port))

    # Send the message
    sock.sctp_send(message)

    # Receive the response
    response = sock.sctp_recv(1024)
    print(f"Response from server: {response.decode('utf-8')}")

    # Close the socket
    sock.close()

if __name__ == "__main__":
    # Update these values with your server details
    server_ip = "192.168.1.100"  # Replace with the actual IP address of the server
    server_port = 12345
    message = b"Hello, SCTP!"

    send_sctp_packet(server_ip, server_port, message)
