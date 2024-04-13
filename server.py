from socket import socket, AF_INET, SOCK_STREAM
from constants import PORT

# Create TCP/IP socket
server_socket: socket = socket(AF_INET, SOCK_STREAM)

server_address: tuple[str, int] = ('localhost', PORT)
server_socket.bind(server_address)

server_socket.listen(5)
print('Server is listening...')

while True:
    # Wait for a connection
    client_socket, client_address = server_socket.accept()
    print(f'Connection from {client_address}')

    # Receive data from the client
    data = client_socket.recv(1024)
    if data:
        print(f'Received: {data.decode()}')

        # Send a response back to the client
        response = 'Message received'
        client_socket.sendall(response.encode())

    # Close the connection
    client_socket.close()
