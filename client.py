from socket import socket, AF_INET, SOCK_STREAM
from constants import PORT, MAX_BUFSIZE

# Create a TCP/IP socket
client_socket: socket = socket(AF_INET, SOCK_STREAM)

# Connect the socket to the server's IP address and port
server_address: tuple[str, int] = ("localhost", PORT)
client_socket.connect(server_address)

try:
    message: str = "Hello, server!"
    client_socket.sendall(message.encode())
    print(f"Sent to server: {message}")

    data = client_socket.recv(MAX_BUFSIZE)
    print(f"Received from server: {data.decode()}")
finally:
    client_socket.close()
