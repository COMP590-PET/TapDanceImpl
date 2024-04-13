from socket import socket, AF_INET, SOCK_STREAM
from constants import PORT, SERVER_BACKLOG, MAX_BUFSIZE

# Create TCP/IP socket
server_socket: socket = socket(AF_INET, SOCK_STREAM)

server_address: tuple[str, int] = ("localhost", PORT)
server_socket.bind(server_address)

server_socket.listen(SERVER_BACKLOG)
print("Server is listening...")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    data: bytes = client_socket.recv(MAX_BUFSIZE)
    if data:
        print(f"Received from client: {data.decode()}")

        response: str = f"Message received: {data.decode()}"
        client_socket.sendall(response.encode())

    client_socket.close()
