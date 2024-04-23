import requests
import socket
import ssl


proxies = {
    "http": "http://127.0.0.1:8080",
}


url = sys.argv[1]                                   ## add bound checks

with open("decoylist.txt", 'r') as file:              ##Choose a random decoysite
    lines = file.read().splitlines()
    decoy = random.choice(lines)

try:                                                ##actually send HTTPS request
    response = requests.get(decoy, proxies=proxies)
    if response.status_code == 200:
        print("HTTPS GET request successful.")
        webbrowser.open(response)                   ##opens it in a browser
    else:
        print(f"Failed: {response.status_code}")
        print(f"Text: {response.text}")



##manually implementing modified TLS 
csocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
csocket.connect(decoy, 443)

context = ssl.create_default_context()
ssl_socket = context.wrap_socket(csocket, hostname=decoy)

#ClientHello
ssl_socket.sendall(b'GET / HTTP/1.1\r\nHost: ' + hostname + '\r\nConnection: close\r\n\r\n')

#serverHello + server cert
response = ssl_socket.recv(4096)
server_cert = ssl_socket.getpeercert()
print(server_cert)

#cert chain
public_key_bytes = server_cert['rsa_public_key']
context = ssl.SSLContext(ssl.PROTOCOL_TLS)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(cafile=None, cadata=None)
context.load_cert_chain(certfile=None, keyfile=None, password=None)
context.load_default_certs()
context.load_cert_chain(certfile=None, keyfile=None, password=None)


context.set_servername(server_address)
context.set_alpn_protocols(['h2', 'http/1.1'])

try
    ssl_socket = context.wrap_socket(client_socket, server_hostname=decoy)
    print("verifed.")
except ssl.CertificateError as e:
    print("failed:", e)


# Close socket
ssl_socket.close()
client_socket.close()

