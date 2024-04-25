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



import pymonocypher as cypher
import os



def KeyGen(stationPK, clientSK, masterK):       ##The client uses the TapDance station’s public key point(P = dG) and its own private key (e) to compute an ECDH shared secret with the station (S = eP = dQ)
    cypher.crypto_x25519(stationPK, clientSK)       #??? 

def TagGen(Key CurveKey, Key Masterkey):        ##Elligator 2 the master secret and generate
    
    tweak = os.urandom(1)
    cypher.crypto_elligator_rev(SSkey, , tweak)
    return tag



def encode(### request, Key Pkey, Tag):       ##attach tag to HTTP request
    self.TagGen()

def decode(### request):       ##recover tag from HTTP request 
    
    return tag

def extract(tag):      ##extract key from recovered key
    cypher.crypto_elligator_map
    