# elliptic curve diffie hellman implementation

import random
import math
import hashlib
import sys
import sympy 


# define the curve
a = 0xfffffffdfffffffffffffffffffffffc
b = 0xe87579c11079f43dd824993c2cee5ed3
p = 0xfffffffdffffffffffffffffffffffff
n = 0xfffffffe0000000075a30d1b9038a115
G = (0x161ff7528b899b2d0c28607ca52c5b86, 0xcf5ac8395bafeb13c02da292dded7a83)

# point addition

def point_addition(point1, point2):
    if point1 == point2:
        slope = ((3 * point1[0]**2 + a))*pow(2 * point1[1], -1, p) % p
    else:
        slope = ((point2[1] - point1[1]) *
                 pow(point2[0] - point2[1], -1, p)) % p
    x = (slope**2 - point1[0] - point2[0]) % p
    y = (slope * (point1[0] - x) - point1[1]) % p
    return (x, y)

# scalar multiplication

def scalar_multiplication(scalar, point):

    binary = bin(scalar)[2:]
    result = point
    for bit in binary[1:]:
        result = point_addition(result, result) 
        if bit == '1':
            result = point_addition(result, point)
    return result

#generate a random number between 2^(128-1) and n-1
k_prA = random.randint(pow(2,127),n-1)

k_prB = random.randint(pow(2,127),n-1)

# public key generation
k_pbA = scalar_multiplication(k_prA, G)
k_pbB = scalar_multiplication(k_prB, G)

# shared key generation
k_sA = scalar_multiplication(k_prA, k_pbB)
k_sB = scalar_multiplication(k_prB, k_pbA)

# print the shared key
print("Shared Key: ",k_sA[0])
print("Shared Key: ",k_sB[0])