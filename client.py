import socket

# Create a TCP/IP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the server's IP address and port
server_address = ('localhost', 12345)
client_socket.connect(server_address)

try:
    # Send data to the server
    message = 'Hello, server!'
    client_socket.sendall(message.encode())

    # Receive the server's response
    data = client_socket.recv(1024)
    print(f'Received: {data.decode()}')

finally:
    # Close the connection
    client_socket.close()
