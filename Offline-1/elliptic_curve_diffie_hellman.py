# elliptic curve diffie hellman implementation

import random
import math
import sympy
import time
import csv

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


def get_a(bit):
    return a[bit]

def get_b(bit):
    return b[bit]

def get_p(bit):
    return p[bit]

def get_n(bit):
    return n[bit]

def get_G(bit):
    return G[bit]

# Function to check if a point is on the curve
def is_point_on_curve(x, y, a, b, p):
    return (y**2) % p == (x**3 + a*x + b) % p

# Function to find a valid point on the curve
def find_point_on_curve(a,b,p):
    #use threading on loop from 0 to p
    # 
    for x in range(0,p):
        y_square = (x**3 + a*x + b) % p
        y = sympy.sqrt_mod(y_square, p)
        #check if y is integer and(x,y) is on the curve and it is not a singular point where slope is infinite
        if y != None and is_point_on_curve(x, y, a, b, p):
            return x,y     
    return None

#generate a,b,p such that the curve is non singular
def generate_curve_parameters(bit):     
    #generate 128 bit prime number for p using sympy
    p = sympy.randprime(pow(2,bit-1),pow(2,bit)-1)
    while True:
        #generate a and b
        a = random.randint(0,p-1)
        b = random.randint(0,p-1)
        #check if the curve is non singular
        if (4*a*a*a + 27*b*b) % p != 0:
            break
    return a,b,p

a_ ,b_, p_ = generate_curve_parameters(128)

print(f"a: {a_}, b: {b_}, p: {p_}")

Gx, Gy = find_point_on_curve(a_, b_, p_)

print(f"Base Point (Gx, Gy): ({Gx}, {Gy})")

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

def point_addition(point1, point2, a, b, p):
    if point1 == point2:
        slope = ((3 * point1[0]**2 + a)%p * inverse_modulo(2 * point1[1], p)) % p
    else:
        slope = ((point2[1] - point1[1])%p * inverse_modulo(point2[0] - point1[0], p)) % p
                
    x = (slope**2 - point1[0] - point2[0]) % p
    y = (slope * (point1[0] - x) - point1[1]) % p
    return (x, y)


# scalar multiplication

def scalar_multiplication(scalar, point, a, b, p):

    binary = bin(scalar)[2:]
    result = point
    for bit in binary[1:]:
        result = point_addition(result, result, a, b, p) 
        if bit == '1':
            result = point_addition(result, point, a, b, p)
    result = (result[0], result[1])
    return result

# bit=128
# #generate a random number between 2^(128-1) and n-1
# k_prA = random.randint(pow(2,127),n[bit]-1)

# k_prB = random.randint(pow(2,127),n[bit]-1)

# # public key generation 
# k_pbA = scalar_multiplication(k_prA, (Gx, Gy), a_, b_, p_)
# k_pbB = scalar_multiplication(k_prB, (Gx, Gy), a_, b_, p_)

# # shared key generation
# k_sA = scalar_multiplication(k_prA, k_pbB, a_, b_, p_)
# k_sB = scalar_multiplication(k_prB, k_pbA , a_, b_, p_)
# # print the shared key
# print("Shared Key: ",k_sA[0])
# print("Shared Key: ",k_sB[0])

# s1=str(bin(k_sA[0])[2:]).zfill(128)
# s2=str(bin(k_sB[0])[2:]).zfill(128)
# #take each 4 bits and convert to hex
# hex_key1=""
# hex_key2=""
# for i in range(0,128,4):
#     hex_key1+=hex(int(s1[i:i+4],2))[2:]
#     hex_key2+=hex(int(s2[i:i+4],2))[2:]

# print("Shared Key: ",hex_key1)
# print("Shared Key: ",hex_key2)
# # no of bits in the shared key
# print("No of bits in the shared key: ", len(hex_key1))
# print("No of bits in the shared key: ", len(hex_key2))

#create a function to compute time for generating A, B, and shared key and return the times
def compute_time(bit):
    k_prA = random.randint(pow(2,127),n[bit]-1)
    k_prB = random.randint(pow(2,127),n[bit]-1)
    start_time = time.time()
    k_pbA = scalar_multiplication(k_prA, G[bit], a[bit], b[bit], p[bit])
    end_time = time.time()
    time_A = end_time - start_time
    start_time = time.time()
    k_pbB = scalar_multiplication(k_prB, G[bit], a[bit], b[bit], p[bit])
    end_time = time.time()
    time_B = end_time - start_time
    start_time = time.time()
    k_sA = scalar_multiplication(k_prA, k_pbB, a[bit], b[bit], p[bit])
    end_time = time.time()
    time_shared_key = end_time - start_time
    return time_A, time_B, time_shared_key
    
def main():
    #save the times in seperate arrays for each bit. arrays are of float type
    time_A_arr = []
    time_B_arr = []
    time_shared_key_arr = []
    for bit in [128, 192, 256]:
        #take average of 5 trials for each bit
        time_A = 0
        time_B = 0

        time_shared_key = 0
        for i in range(5):
            time_A_temp, time_B_temp, time_shared_key_temp = compute_time(bit)
            time_A += time_A_temp
            time_B += time_B_temp
            time_shared_key += time_shared_key_temp
        time_A /= 5
        time_B /= 5
        time_shared_key /= 5
        
        time_A_arr.append("{:.3f}".format(time_A*1000))
        time_B_arr.append("{:.3f}".format(time_B*1000))
        time_shared_key_arr.append("{:.3f}".format(time_shared_key*1000))
    # print the times in a table
    print("----------------------------------------------------------------------------------------------------------------------")
    print("K            |            A                   |                   B              |                R             ")
    print("----------------------------------------------------------------------------------------------------------------------")
    print("128          |       ",time_A_arr[0],"                  |",time_B_arr[0],"                           |       ",time_shared_key_arr[0])
    print("----------------------------------------------------------------------------------------------------------------------")
    print("192          |       ",time_A_arr[1],"                  |",time_B_arr[1],"                           |       ",time_shared_key_arr[1])
    print("----------------------------------------------------------------------------------------------------------------------")
    print("256          |       ",time_A_arr[2],"                 |",time_B_arr[2],"                          |     ",time_shared_key_arr[2])
    print("----------------------------------------------------------------------------------------------------------------------")   

if __name__ == "__main__":
    main()
