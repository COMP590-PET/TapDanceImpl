import os
import socket
import ssl

# Specify the path for the SSL key log file
key_log_file = "ssl_key.log"
os.environ["SSLKEYLOGFILE"] = key_log_file


def tls_handshake_through_proxy(host, proxy_host, proxy_port, target_port):
    # Create a raw socket
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
    #request = "GET / HTTP/1.1\r\nHost: " 
    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive"
    wrapped_socket.sendall(request.encode())
    print("HTTP Request Sent")

    # Receive some data
    response = wrapped_socket.recv(4096)
    print("HTTP Response Received")
    print(response.decode())

    # Close the socket
    wrapped_socket.close()

def reset_key_log_file():
    with open(key_log_file, "w") as file:
        # Opening in write mode truncates the file to 0 bytes if it exists
        pass 

def print_ssl_keys():
    try:
        with open(key_log_file, "r") as file:
            print("TLS Session Keys:")
            print(file.read())
    except FileNotFoundError:
        print(
            "Key log file not found. Ensure that the SSLKEYLOGFILE is set correctly and the session is initiated."
        )

def get_client_traffic_secret_0():
    try:
        with open(key_log_file, "r") as file:
            lines = file.readlines()
            for line in lines:
                if "CLIENT_TRAFFIC_SECRET_0" in line:
                    # Extracts the secret which is the third part of the line
                    secret = line.strip().split(" ")[-1]
                    return secret
    except FileNotFoundError:
        print(
            "Key log file not found. Ensure that the SSLKEYLOGFILE is set correctly and the session is initiated."
        )
    return None  # 

# Example usage
if __name__ == "__main__":
    reset_key_log_file() 
    tls_handshake_through_proxy("www.bing.com", "localhost", 8080, 443)
    