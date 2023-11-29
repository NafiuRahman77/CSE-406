# elliptic curve diffie hellman implementation

import random
import math
import sympy 


# define the curve
#make dictionary 'a' like 128:0xfffffffdfffffffffffffffffffffffc

a=  {128:0xfffffffdfffffffffffffffffffffffc, 192:0xfffffffffffffffffffffffffffffffefffffffffffffffc, 256:0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc}
b = {128: 0xe87579c11079f43dd824993c2cee5ed3,192:0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,256:0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b}
p = {128:0xfffffffdffffffffffffffffffffffff,192:0xfffffffffffffffffffffffffffffffeffffffffffffffff,256:0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff}
n = {128: 0xfffffffe0000000075a30d1b9038a115, 192:0xffffffffffffffffffffffff99def836146bc9b1b4d22831, 256:0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551}
G = {128: (0x161ff7528b899b2d0c28607ca52c5b86, 0xcf5ac8395bafeb13c02da292dded7a83), 
     192:(0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811),
     256: (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
     }


# inverse modulo

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

def inverse_modulo(a, m):
    if a < 0 or m <= a:
        a = a % m
    gcd, x, y = extended_gcd(a, m)
    return (x % m + m) % m

# point addition

def point_addition(point1, point2, k):
    if point1 == point2:
        slope = ((3 * point1[0]**2 + a[k])%p[k] * inverse_modulo(2 * point1[1], p[k])) % p[k]
    else:
        slope = ((point2[1] - point1[1])%p[k] * inverse_modulo(point2[0] - point1[0], p[k])) % p[k]
                
    x = (slope**2 - point1[0] - point2[0]) % p[k]
    y = (slope * (point1[0] - x) - point1[1]) % p[k]
    return (x, y)


# scalar multiplication

def scalar_multiplication(scalar, point, k):

    binary = bin(scalar)[2:]
    result = point
    for bit in binary[1:]:
        result = point_addition(result, result, k) 
        if bit == '1':
            result = point_addition(result, point, k)
    result = (result[0], result[1])
    return result

bit=128
#generate a random number between 2^(128-1) and n-1
k_prA = random.randint(pow(2,127),n[bit]-1)

k_prB = random.randint(pow(2,127),n[bit]-1)

# public key generation 
k_pbA = scalar_multiplication(k_prA, G[bit], bit)
k_pbB = scalar_multiplication(k_prB, G[bit], bit)

# shared key generation
k_sA = scalar_multiplication(k_prA, k_pbB, bit)
k_sB = scalar_multiplication(k_prB, k_pbA , bit)
# print the shared key
print("Shared Key: ",k_sA[0])
print("Shared Key: ",k_sB[0])

