from OpenSSL import SSL, crypto
from OpenSSL.SSL import Context, TLS_METHOD, TLS_CLIENT_METHOD, TLSv1_2_METHOD, Connection
from socket import socket, AF_INET, SOCK_STREAM, gethostbyname, create_connection
from constants import BADSSL_TLS_1_2_PORT

site: str = f"tls-v1-2.badssl.com:{BADSSL_TLS_1_2_PORT}"

ctx: Context = Context(TLSv1_2_METHOD)

proxy_sock: socket = socket(AF_INET, SOCK_STREAM)
proxy_sock.connect(("127.0.0.1", 8080))
connection: Connection = Connection(ctx, proxy_sock)
connection.set_tlsext_host_name(site.encode())
connection.set_connect_state()
connection.do_handshake()
print(f"Did handshake with {site} through proxy server {proxy_sock.getpeername()}")

master_key = connection.master_key()
print(f"TLS handshake master key: {master_key}")

request = f"GET / HTTP/1.1\r\nHost: {site}\r\nConnection: close\r\n\r\n"
connection.sendall(request.encode())

response = b""
try:
    while True:
        data = connection.recv(4096)
        if not data:
            break
        response += data
except SSL.SysCallError as e:
    pass
finally:
    print(f"Received response: {response.decode()}")
    proxy_sock.close()
