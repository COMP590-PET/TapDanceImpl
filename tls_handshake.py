# Doesn't work, use sslkeylog instead

from OpenSSL import SSL, crypto
from OpenSSL.SSL import Context, TLS_METHOD, TLS_CLIENT_METHOD, Connection
from socket import socket, AF_INET, SOCK_STREAM, gethostbyname, create_connection
from constants import HTTPS_PORT, HTTP_PORT

ctx: Context = Context(TLS_CLIENT_METHOD)

sock: socket = socket(AF_INET, SOCK_STREAM)
sock.connect(("google.com", HTTPS_PORT))

connection: Connection = Connection(ctx, sock)

connection.set_connect_state()
connection.do_handshake()

master_key = connection.master_key()

print(master_key)

# sock = socket(AF_INET, SOCK_STREAM)
# google_ip = gethostbyname("google.com")

# ssl_socket = SSL.Connection(ctx, client_socket)
# ssl_socket.connect((google_ip, HTTPS_PORT))

# https_request = (
#     "GET / HTTP/1.1\r\n"
#     "Host: reddit.com\r\n"
#     "Connection: close\r\n"  # Close the connection after receiving the response
#     "\r\n"
# )
# ssl_socket.send(https_request.encode())

# response = b""
# try:
#     while True:
#         data = ssl_socket.recv(1024)
#         if not data:
#             break
#         response += data
# except SSL.SysCallError as e:
#     pass
# finally:
#     print(response.decode())
#     ssl_socket.close()
