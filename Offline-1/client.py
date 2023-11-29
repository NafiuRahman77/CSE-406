# #simple tcp client program
import socket
import pickle
import aes as aes

import elliptic_curve_diffie_hellman as ecdh

import random

# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = socket.gethostname()

port = 9999

# connection to hostname on the port.
s.connect((host, port))

#get elliptic curve parameters from ecdh

bit=128
a=ecdh.get_a(bit)
b=ecdh.get_b(bit)
p=ecdh.get_p(bit)
n=ecdh.get_n(bit)
G=ecdh.get_G(bit)

#generate private key
k_prA = random.randint(pow(2,bit-1),n-1)

# public key generation
k_pbA = ecdh.scalar_multiplication(k_prA, G, bit)

#send public key, k_pbA which is a tuple to server
s.send(pickle.dumps(k_pbA))

#receive public key from server
server_public_key = pickle.loads(s.recv(1024))


#shared secret generation
shared_secret = ecdh.scalar_multiplication(k_prA, server_public_key , bit)

secret = shared_secret[0]
secret = str(bin(secret)[2:]).zfill(128)

secret_hex=""

for i in range(0,128,4):
    secret_hex+=hex(int(secret[i:i+4],2))[2:]

print("Shared Key: ",secret_hex)

plain_text="Never Gonna Give you up"
key=secret_hex
ciphered=aes.aes_encryption(plain_text,key,True)
print("Ciphered: ",ciphered[1])
s.send(ciphered[1].encode('ascii'))

# Receive no more than 1024 bytes
msg = s.recv(1024)

print(msg.decode('ascii'))

s.close()

