from OpenSSL import SSL, crypto
from OpenSSL.SSL import Context, TLS_METHOD
from socket import socket, AF_INET, SOCK_STREAM, gethostbyname
from constants import HTTPS_PORT, HTTP_PORT

ctx: Context = Context(TLS_METHOD)

client_socket = socket(AF_INET, SOCK_STREAM)
google_ip = gethostbyname("google.com")

ssl_context = SSL.Context(TLS_METHOD)
ssl_socket = SSL.Connection(ssl_context, client_socket)
ssl_socket.connect((google_ip, HTTPS_PORT))

https_request = (
    "GET / HTTP/1.1\r\n"
    "Host: google.com\r\n"
    "Connection: close\r\n"  # Close the connection after receiving the response
    "\r\n"
)
ssl_socket.send(https_request.encode())

response = b""
try:
    while True:
        data = ssl_socket.recv(1024)
        if not data:
            break
        response += data
except SSL.SysCallError as e:
    pass
finally:
    print(response.decode())
    ssl_socket.close()
