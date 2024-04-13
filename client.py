from socket import socket, AF_INET, SOCK_STREAM
from constants import PORT

# Create a TCP/IP socket
client_socket = socket(AF_INET, SOCK_STREAM)

# Connect the socket to the server's IP address and port
server_address = ("localhost", PORT)
client_socket.connect(server_address)

try:
    # Send data to the server
    message = "Hello, server!"
    client_socket.sendall(message.encode())

    # Receive the server's response
    data = client_socket.recv(1024)
    print(f"Received: {data.decode()}")

finally:
    # Close the connection
    client_socket.close()
