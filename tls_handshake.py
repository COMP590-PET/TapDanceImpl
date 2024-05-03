from OpenSSL import SSL, crypto
from OpenSSL.SSL import Context, TLS_METHOD, TLS_CLIENT_METHOD, Connection
from socket import socket, AF_INET, SOCK_STREAM, gethostbyname, create_connection
from constants import BADSSL_TLS_1_2_PORT

site: str = "tls-v1-2.badssl.com"

ctx: Context = Context(TLS_CLIENT_METHOD)

sock: socket = socket(AF_INET, SOCK_STREAM)
sock.connect((site, BADSSL_TLS_1_2_PORT))
connection: Connection = Connection(ctx, sock)
connection.set_connect_state()
connection.do_handshake()
print(f"Did handshake with {site} over port {BADSSL_TLS_1_2_PORT}")

master_key = connection.master_key()
print(f"TLS handshake master key: {master_key}")
