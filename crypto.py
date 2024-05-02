##The client uses the TapDance station’s public key point
##(P = dG) and its own private key (e) to compute an ECDH
##shared secret with the station (S = eP = dQ), which is
##used to derive the payload encryption key. The encrypted
##payload contains an 8-byte magic value used by the sta-
##tion to detect successful decryption, the client and server
##random nonces, and the client-server master secret of the
##TLS connection. With this payload, typically contained
##in a single packet from the client, the station is able to
##derive the TLS master secret between client and server



import monocypher as cypher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

magic_value = os.urandom(8)
seed = b'\x1d\xed\x81p\xe7Zdr\xf8\xa79\xa3\xed\xb5\xf9\xcb\xcc.\xd5\x04\xf7Z;\xfc\x81*^C/\x1e8('
# client_hidden, client_sk = cypher.elligator_key_pair(seed)
# client_pk = cypher.elligator_map(client_hidden)
# curve1 = cypher.elligator_map(client_hidden)

client_sk = X25519PrivateKey.generate()
client_pk = client_sk.public_key()

station_sk = X25519PrivateKey.generate() # we don't know this obv
station_pk = station_sk.public_key()

##The client uses the TapDance station’s public key point(P = dG) and its own private key (e) to compute an ECDH shared secret with the station (S = eP = dQ)
def key_gen(stationPK, clientSK):       
    shared_secret = clientSK.exchange(stationPK)    
    shared_hash = HKDF( # Use a cryptographic hash function to derive the key from the shared secret
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',).derive(shared_secret)
    return shared_hash

def generate_payload(stationPK, clientSK, master_secret, client_random, server_random):
    # Compute the ECDH shared secret and get the shared key
    shared_hash = key_gen(stationPK, clientSK)

    # Combine the encoded client public key, magic value, master secret, and nonces into a single payload
    payload = magic_value + master_secret + client_random + server_random

    # Encrypt the payload using the derived key
    # Use first 16 bytes of shared hash as key and last 16 bytes as IV
    key = shared_hash[:16]
    iv = shared_hash[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) # Use AES in CBC mode
    encryptor = cipher.encryptor()
    encrypted_payload = encryptor.update(payload) + encryptor.finalize()

    return encrypted_payload

#32-byte encoded/hidden client public key
def generate_encoded_pk(clientPK):
    encoded_pk = cypher.elligator_rev(clientPK, os.urandom(1)[0])
    return encoded_pk

def generate_tag(stationPK, clientSK, clientPK, master_secret, client_random, server_random):       
    tag = generate_encoded_pk(clientPK) + generate_payload(stationPK, clientSK, master_secret, client_random, server_random)
    return tag

def decode(### request):       ##recover tag from HTTP request 
    
    return tag

def extract(tag):      ##extract key from recovered key
    cypher.crypto_elligator_map

# to use map, syntax is: cypher.elligator_map(encoded_pk), which returns the decoded public key


    