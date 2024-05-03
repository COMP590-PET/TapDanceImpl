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
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64decode
from base64 import b64encode
import os
from bitstring import BitArray

magic_value = os.urandom(8)
seed = b'\x1d\xed\x81p\xe7Zdr\xf8\xa79\xa3\xed\xb5\xf9\xcb\xcc.\xd5\x04\xf7Z;\xfc\x81*^C/\x1e8('
# client_hidden, client_sk = cypher.elligator_key_pair(seed)
# client_pk = cypher.elligator_map(client_hidden)
# curve1 = cypher.elligator_map(client_hidden)

client_sk = X25519PrivateKey.generate()
client_pk = client_sk.public_key()


station_sk = X25519PrivateKey.generate() # we don't know this obv
station_pk = station_sk.public_key()

def encrypt_aes_cbc(key, plaintext, iv):
    # Ensure plaintext length is a multiple of AES block size (16 bytes)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def decrypt_aes_cbc(key, ciphertext, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]
    return plaintext

##The client uses the TapDance station’s public key point(P = dG) and its own private key (e) to compute an ECDH shared secret with the station (S = eP = dQ)
def key_gen(stationPK, clientSK):       
    shared_secret = clientSK.exchange(stationPK)    
    shared_hash = HKDF( # Use a cryptographic hash function to derive the key from the shared secret
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',).derive(shared_secret)
    return shared_hash

def generate_payload(stationPK, clientSK, master_secret, client_random, server_random, connection_ID):
    # Compute the ECDH shared secret and get the shared key
    shared_hash = key_gen(stationPK, clientSK)

    # Combine the encoded client public key, magic value, master secret, and nonces into a single payload
    payload = magic_value + master_secret + client_random + server_random + connection_ID + b"00000000"
    print("payload: ",len(payload))

    # Encrypt the payload using the derived key
    # Use first 16 bytes of shared hash as key and last 16 bytes as IV
    key = shared_hash[:16]
    iv = shared_hash[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) # Use AES in CBC mode
    encryptor = cipher.encryptor()
    encrypted_payload = encryptor.update(payload) + encryptor.finalize()
    print("enc_pay", len(encrypted_payload))

    return encrypted_payload

#32-byte encoded/hidden client public key
def generate_encoded_pk(clientPK):
    encoded_pk = cypher.elligator_rev(clientPK.public_bytes_raw(), os.urandom(1)[0])
    return encoded_pk

def generate_tag(stationPK, clientSK, clientPK, master_secret, client_random, server_random, connection_ID):    
    print("tag",len(generate_encoded_pk(clientPK)))   
    tag = generate_encoded_pk(clientPK) + generate_payload(stationPK, clientSK, master_secret, client_random, server_random, connection_ID)
    return tag

def decode_pk(hidden):       ## decode hidden public key using Elligator2
    return cypher.elligator_map(hidden)

def extract(tag, stationSK):      ##extract secrets from received tag
    clientPK = X25519PublicKey.from_public_bytes(decode_pk(tag[:32]))
    shared_hash = key_gen(clientPK, stationSK)

    # Decrypt the payload using the derived key
    key = shared_hash[:16]
    iv = shared_hash[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_payload = decryptor.update(tag[32:]) + decryptor.finalize()

    # Check magic value to ensure decryption was successful and intent to proxy
    if decrypted_payload[:8] != magic_value:
        raise Exception("Magic value mismatch")
    
    # Extract the master secret from the decrypted payload
    secrets = { "master_secret": decrypted_payload[8:56], 
               "client_random": decrypted_payload[56:88], 
               "server_random": decrypted_payload[88:120], 
               "connection_ID": decrypted_payload[120:136] }
    
    return secrets

# Generate the tag and extract the secrets

master_key = b't\t\xa9\xb0\xf2\x1f\xc6\xd3wI<\xfb@|\xee\xba\xdc\n\xac\xad\xc1\x14Ik\xdc\x96\xbd\xbaH\x94!\xfe\xb0\x9a\xeeW\xfb\xa60<\xb5\x80\x96\xdc \xb7lC'
print(len(master_key))
client_random = os.urandom(32)
server_random = os.urandom(32)
connection_ID = os.urandom(16)
tag = generate_tag(station_pk, client_sk, client_pk, master_key, client_random, server_random, connection_ID)
key = key_gen(station_pk, client_sk)

def split_ciphertext(ciphertext, block_size=16):
    """Splits the ciphertext into blocks of the specified size."""
    assert len(ciphertext) % block_size == 0, "Ciphertext length must be a multiple of the block size."
    return [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

def encrypt_aes_cbc_single_block(key, plaintext, iv):
    assert len(plaintext) == 16, "Plaintext must be exactly one block (16 bytes) long."
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) 
    return ciphertext

def decrypt_aes_cbc_single_block(key, ciphertext, iv):
    assert len(ciphertext) == 16, "Ciphertext must be exactly one block (16 bytes) long."
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def decrypt_aes_cbc(p0, key ,tag):
    blocks = split_ciphertext(tag)
    pt = b""
    for i in range(len(blocks)-1,0,-1):
        p_temp = decrypt_aes_cbc_single_block(key,blocks[i],blocks[i-1]) 
        pt = p_temp + pt

    p_temp = decrypt_aes_cbc_single_block(key,blocks[0],p0) 
    pt = p0 + pt
    return pt, p_temp


print("Generated Tag:")
print(tag)
p0 = os.urandom(16)
pt,iv = decrypt_aes_cbc(p0,key,tag)
print()

print("Generated Plaintet")
print(pt)
print()
print("Generated Tag from the plaintext using AES-CBC")
print(encrypt_aes_cbc(key,pt,iv))


print("Extracted Secrets:")
secrets = extract(tag, station_sk)
print(secrets)

    