#simple tcp server program without threading
import socket

import aes as aes

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

while True:
    # establish a connection
    clientsocket,addr = serversocket.accept()
    print("Got a connection from %s" % str(addr))
    key = clientsocket.recv(1024)
    print("Received message: %s" % key.decode('ascii'))
    cipher_text = clientsocket.recv(1024)
    print("Received message: %s" % cipher_text.decode('ascii'))
    plain_text=aes.aes_decryption(cipher_text.decode('ascii'),key.decode('ascii'))
    
    msg = 'Thank you for connecting'+ "\r\n"
    clientsocket.send(msg.encode('ascii'))
    clientsocket.close()

