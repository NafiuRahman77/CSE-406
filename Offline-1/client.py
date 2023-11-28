# #simple tcp client program
import socket

import aes as aes

# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = socket.gethostname()

port = 9999

# connection to hostname on the port.
s.connect((host, port))

plain_text="Never Gonna Give you up"
key="BUET CSE19 Batch"
s.send(key.encode('ascii'))
ciphered=aes.aes_encryption(plain_text,key)
print("Ciphered: ",ciphered[1])
s.send(ciphered[1].encode('ascii'))

# Receive no more than 1024 bytes
msg = s.recv(1024)

print(msg.decode('ascii'))

s.close()

