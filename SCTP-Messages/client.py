import sctp
import socket
import time
import random
import string

def generate_random_message():
    message_length = random.randint(5, 20)
    random_message = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(message_length))
    return random_message.encode('utf-8')

def send_sctp_random_messages(server_ip, server_port, interval=1):
    # Create a new SCTP socket
    sock = sctp.sctpsocket_tcp(socket.AF_INET)

    # Connect to the server
    sock.connect((server_ip, server_port))

    try:
        while True:
            # Generate a random message
            message = generate_random_message()

            # Send the message
            sock.sctp_send(message)

            print(f"Sent random message: {message.decode('utf-8')}")

            # Receive the response
            response = sock.sctp_recv(1024)
            print(f"Response from server: {response.decode('utf-8')}")

            # Wait for the specified interval before sending the next message
            time.sleep(interval)

    except KeyboardInterrupt:
        print("Program stopped by user.")

    finally:
        # Close the socket
        sock.close()

if __name__ == "__main__":
    # Update these values with your server details
    server_ip = "192.168.1.100"  # Replace with the actual IP address of the server
    server_port = 12345

    send_sctp_random_messages(server_ip, server_port)
