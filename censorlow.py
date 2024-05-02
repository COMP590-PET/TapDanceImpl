from mitmproxy import http
import logging
import re
from constants import CENSOR_BLOCKED_URLS, ISP_REFRACT_URLS
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_public_key(filename):
    with open(filename, 'rb') as f:
        public_key = load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

class BlockResource:
    def __init__(self):
        logging.info(f"{len(CENSOR_BLOCKED_URLS)} censored URL's read")
        logging.info(f"{len(ISP_REFRACT_URLS)} refract URL's read")
        self.private_key = x25519.X25519PrivateKey.generate()
        # Get public key from private key
        self.public_key = self.private_key.public_key()

        # Serialize the public key to PEM format
        self.pem_public = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Serialize public key and save it to a file
        self.save_public_key()

    def save_public_key(self):
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open('public_key_isp.pem', 'wb') as f:
            f.write(pem)
        logging.info("Public key saved to file.")

    def request(self, flow: http.HTTPFlow) -> None:
        logging.info(f"ACK: Received HTTP request for {flow.request.pretty_url}")
        self.censor(flow)
        if self.check_incomplete_request(flow):
            logging.info("Detected incomplete https request")
            #public_key_client = load_public_key("public_key_client.pem")
            #shared_secret = self.private_key.exchange(ec.ECDH(), public_key_client)
            #derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
            #derived_key.update(shared_secret)
            #final_key = derived_key.finalize()

            self.isp_redirect(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        # Simulate TCP ACK by modifying the response
        if flow.response:
            flow.response.headers["x-tcp-simulation"] = "ACK for response"
            logging.info(f"ACK: Sent HTTP response for {flow.request.pretty_url}")

    def censor(self, flow: http.HTTPFlow) -> None:
        # Check if the URL is in the blocked list and censor it
        if any(re.search(pattern, flow.request.url) for pattern in CENSOR_BLOCKED_URLS):
            logging.info(f"Censoring URL: {flow.request.url}")
            flow.response = http.Response.make(
                404,  # Status code
                b"This URL has been censored.",  # Response body
                {"Content-Type": "text/plain"}  # Headers
            )

    def isp_redirect(self, flow: http.HTTPFlow) -> None:
        # Redirect URLs based on ISP-specific rules
        if any(re.search(pattern, flow.request.url) for pattern in ISP_REFRACT_URLS):
            logging.info(f"Redirecting {flow.request.url} to www.youtube.com")
            flow.request.host = "www.youtube.com"

    def load_private_key(filename):
        with open(filename, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        return private_key

    def decrypt_data(private_key, encrypted_data):
        try:
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_data
        except Exception as e:
            logging.error("Decryption failed: {}".format(e))
            return None

    def check_incomplete_request(self, flow: http.HTTPFlow) -> bool:
        logging.info("testing incompleteness")
        logging.info("Content-Length" in flow.request.headers)
        if "Content-Length" in flow.request.headers:
            content_length = int(flow.request.headers["Content-Length"])
            actual_length = len(flow.request.content)
            if actual_length < content_length:
                logging.warning(f"Incomplete HTTP request detected for {flow.request.url}")
                
                # Assuming the encrypted data is the received part of the body
                encrypted_data = flow.request.content
                private_key = self.load_private_key('private_key_isp.pem')  # Ensure this path and method are correct
                decrypted_data = self.decrypt_data(private_key, encrypted_data)
                
                if decrypted_data:
                    logging.info("Decrypted Data: {}".format(decrypted_data))
                else:
                    logging.error("Failed to decrypt data.")
                
                flow.response = http.Response.make(
                    400, b"Incomplete HTTP request", {"Content-Type": "text/plain"}
                )
                return True
        return False

addons = [
    BlockResource()
]
