import os
import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Specify the path for the SSL key log file

def generate_keys():
    # Generate private key for RSA encryption
    private_key = x25519.X25519PrivateKey.generate()
    # Get public key from private key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, pem_public

def save_public_key(public_key, filename_suffix):
    with open(f'public_key_{filename_suffix}.pem', 'wb') as f:
        f.write(public_key)

def load_public_key(filename):
    with open(filename, 'rb') as f:
        public_key = load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def tls_handshake_through_proxy(host, proxy_host, proxy_port, target_port, private_key_client, public_key_server):
    # Create a raw socket
    shared_secret = private_key_client.exchange(public_key_server)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

    message = b'Confidential Message'
    aes_gcm = Cipher(algorithms.AES(derived_key), modes.GCM(b'\x00'*12), backend=default_backend())
    encryptor = aes_gcm.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag



    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    # Connect to mitmproxy
    sock.connect((proxy_host, proxy_port))

    # Correctly formatted CONNECT request
    connect_request = f"CONNECT {host}:{target_port} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    sock.sendall(connect_request.encode())

    # Wait for the proxy to respond with a successful connection
    response = b""
    while True:
        part = sock.recv(4096)
        response += part
        if b"\r\n\r\n" in part:
            break

    response = response.decode()
    if "200 Connection established" not in response:
        print("Failed to connect through proxy")
        print(response)
        sock.close()
        return

    # Create SSL context and wrap the socket after the CONNECT
    context = ssl.create_default_context()
    context.load_verify_locations(
        "mitmproxy-ca-cert.pem"
    )  # Ensure this path is correct
    wrapped_socket = context.wrap_socket(
        sock, server_hostname=host, do_handshake_on_connect=True
    )
    print("TLS Handshake Completed")

    # After the handshake, you can send some data or request
    #request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    request = f"POST /secret HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(encrypted_message) + len(tag)}"
    #wrapped_socket.sendall(request.encode())
    wrapped_socket.sendall(request.encode() + encrypted_message + tag)
    print("HTTP Request Sent")

    # Receive some data
    response = wrapped_socket.recv(4096)
    print("HTTP Response Received")
    print(response.decode())

    # Close the socket
    wrapped_socket.close()

# Example usage
if __name__ == "__main__":
    private_key_client, public_key_client = generate_keys()
    public_key_server = load_public_key('public_key_isp.pem')
    save_public_key(public_key_client, 'client')
    tls_handshake_through_proxy("www.youtube.com", "localhost", 8080, 443, private_key_client, public_key_server)

