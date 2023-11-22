# #simple tcp client program
import socket

# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = socket.gethostname()

port = 9999

# connection to hostname on the port.
s.connect((host, port))

s.send("Hello server!\r\n".encode('ascii'))

# Receive no more than 1024 bytes
msg = s.recv(1024)

print(msg.decode('ascii'))

s.close()

