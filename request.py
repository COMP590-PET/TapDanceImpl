from OpenSSL import SSL
import socket

def get_session_keys(host, port):
    # Set up a context with a specific method
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)

    # Create a socket and wrap it in an SSL connection
    sock = socket.create_connection((host, port))
    connection = SSL.Connection(context, sock)

    # Perform the handshake
    connection.set_tlsext_host_name(host.encode())
    connection.do_handshake()

    # After handshake, attempt to access session keys
    session = connection.get_session()
    master_key = session.master_key()
    session_id = session.session_id()

    print(f"Master Key: {master_key.hex()}")
    print(f"Session ID: {session_id.hex()}")

    # Clean up
    connection.shutdown()
    connection.close()
    sock.close()

# Use the function with your target
get_session_keys('duckduckgo.com', 443)
