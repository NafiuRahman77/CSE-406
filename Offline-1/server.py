# simple tcp server program without threading
import socket

import aes as aes
import elliptic_curve_diffie_hellman as ecdh
import pickle
import random

# create a socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = socket.gethostname()

port = 9999

# bind to the port
serversocket.bind((host, port))

# queue up to 5 requests
serversocket.listen(5)

print("Server started")

# get elliptic curve parameters from ecdh

bit = 128
a = ecdh.get_a(bit)
b = ecdh.get_b(bit)
p = ecdh.get_p(bit)
n = ecdh.get_n(bit)
G = ecdh.get_G(bit)


while True:
    # establish a connection
    clientsocket, addr = serversocket.accept()
    print("Got a connection from %s" % str(addr))

    # generate private key
    k_prB = random.randint(pow(2, bit-1), n-1)
    # public key generation
    k_pbB = ecdh.scalar_multiplication(k_prB, G, bit)
    # receive public key from client
    client_public_key = pickle.loads(clientsocket.recv(1024))
    # send public key to client
    clientsocket.send(pickle.dumps(k_pbB))

    # shared secret generation
    shared_secret = ecdh.scalar_multiplication(
        k_prB, client_public_key , bit)

    secret = shared_secret[0]
    secret = str(bin(secret)[2:]).zfill(128)

    secret_hex = ""

    for i in range(0, 128, 4):
        secret_hex += hex(int(secret[i:i+4], 2))[2:]

    print("Shared Key: ",secret_hex)
 
    cipher_text = clientsocket.recv(1024)
    print("Ciphered: ",cipher_text.decode('ascii'))
    plain_text = aes.aes_decryption(
        cipher_text.decode('ascii'), secret_hex)
    print("Deciphered: ",plain_text)
    msg = 'Thank you for connecting' + "\r\n"

    clientsocket.send(msg.encode('ascii'))
    clientsocket.close()
