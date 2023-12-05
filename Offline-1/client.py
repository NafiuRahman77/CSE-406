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
a, b, p = ecdh.generate_curve_parameters(bit)
Gx, Gy = ecdh.find_point_on_curve(a, b, p)
G = (Gx, Gy)

#send curve parameters to server
s.send(pickle.dumps((a,b,p,G)))


#generate private key
k_prA = random.randint(2,p-1)

# public key generation
k_pbA = ecdh.scalar_multiplication(k_prA, G, a, b, p)

#send public key, k_pbA which is a tuple to server
s.send(pickle.dumps(k_pbA))

#receive public key from server
server_public_key = pickle.loads(s.recv(1024))

#shared secret generation
shared_secret = ecdh.scalar_multiplication(k_prA, server_public_key , a, b, p)

secret = shared_secret[0]
secret = str(bin(secret)[2:]).zfill(128)

secret_hex=""

for i in range(0,128,4):
    secret_hex+=hex(int(secret[i:i+4],2))[2:]

print("Shared Key: ",secret_hex)


#generate private iv
iv_prA = random.randint(2,p-1)

# public iv generation
iv_pbA = ecdh.scalar_multiplication(iv_prA, G, a, b, p)

#send public iv, iv_pbA which is a tuple to server
s.send(pickle.dumps(iv_pbA))

#receive public iv from server
server_public_iv = pickle.loads(s.recv(1024))

#shared secret generation
shared_iv = ecdh.scalar_multiplication(iv_prA, server_public_iv , a, b, p)

iv = shared_iv[0]
iv = str(bin(iv)[2:]).zfill(128)

iv_hex=""

for i in range(0,128,4):
    iv_hex+=hex(int(iv[i:i+4],2))[2:]

print("Shared iv: ",iv_hex)


plain_text="Lorem ipsum dolor sit amet, consecte tur adipiscing elit. Aliquam id orci ut lectus varius viverra. Nullam nunc ex, convallis sed semper quis, max imus nec nisi"
key=secret_hex
ciphered=aes.aes_cbc_encryption(plain_text,key,True, iv_hex)
print("Ciphered: ",ciphered[1])
s.send(pickle.dumps(ciphered))

# Receive no more than 1024 bytes
msg = s.recv(1024)

print(msg.decode('ascii'))

s.close()

