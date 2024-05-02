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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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
        self.incomplete_detected = False 
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

        #logging.info(f"ACK: Received HTTP request for {flow.request.pretty_url}")
        #request = flow.request
        #logging.info(request)
        #logging.warning(request.endswith("\r\n\r\n"))
        #logging.info("Received HTTP Request:")
        #logging.info(f"Method: {request.method}")
        #logging.info(f"URL: {request.pretty_url}")
        #logging.info(f"Headers: {request.headers}")
        #if request.content:
        #    logging.info(f"Body: {request.content}")
        self.censor(flow)
        #logging.info(f"ACK: Received HTTP request for {flow.request.pretty_url}")
    
        #First, check for an incomplete request
        #if not self.check_incomplete_request(flow):
        logging.info("Detected incomplete HTTPS request.")
        if any(re.search(pattern, flow.request.url) for pattern in ISP_REFRACT_URLS):
            logging.info(f"Redirecting to {flow.request.url} due to prior incomplete request.")
            flow.request.host = "www.bing.com"
            self.incomplete_detected = False 

        

        """if self.check_incomplete_request(flow):
            logging.info("Detected incomplete https request")
            public_key_client = load_public_key("public_key_client.pem")
            shared_secret = self.private_key.exchange(public_key_client)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_secret)
     
            self.isp_redirect(flow)
        """

    def censor(self, flow: http.HTTPFlow) -> None:
        # Check if the URL is in the blocked list and censor it
        if any(re.search(pattern, flow.request.url) for pattern in CENSOR_BLOCKED_URLS):
            logging.info(f"Censoring URL: {flow.request.url}")
            flow.response = http.Response.make(
                404,  # Status code
                b"This URL has been censored.",  # Response body
                {"Content-Type": "text/plain"}  # Headers
            )
        #logging.info(flow.response.content)

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
        logging.info("Checking for header completeness in the request")
        logging.info(flow.request.content[-4:])
        if not flow.request.content: return True
        if flow.request.content[-4:] == b"\r\n\r\n":
            return True
        return False
    
        
addons = [
    BlockResource()
]
