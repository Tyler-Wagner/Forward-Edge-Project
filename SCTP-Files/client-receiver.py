import sctp
import socket
import time

def send_sctp_file(server_ip, server_port, filename):
    # Create a new SCTP socket
    sock = sctp.sctpsocket_tcp(socket.AF_INET)

    # Connect to the server
    sock.connect((server_ip, server_port))

    # Read the file content
    with open(filename, 'rb') as file:
        file_content = file.read()

    # Send the file content
    sock.sctp_send(file_content)

    print(f"Sent file: {filename}")

    # Receive the response
    response = sock.sctp_recv(1024)
    print(f"Response from server: {response.decode('utf-8')}")

    # Close the socket
    sock.close()

def main():
    # Update these values with your server details
    server_ip = "192.168.1.100"  # Replace with the actual IP address of the server
    server_port = 12345
    filename_to_send = "file_to_send.txt"

    try:
        while True:
            # Send the file to the server
            send_sctp_file(server_ip, server_port, filename_to_send)

            # Wait for 3 minutes
            time.sleep(180)

    except KeyboardInterrupt:
        print("Program stopped by user.")

if __name__ == "__main__":
    main()
