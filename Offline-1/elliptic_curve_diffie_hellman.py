# elliptic curve diffie hellman implementation

import random
import math
import hashlib
import sys
import sympy 

#generate prime number of 128 bits
def generate_prime_number():
    prime = sympy.randprime(pow(2,127),pow(2,128))
    return prime

# define the curve
a = 1
b = 6
p = 11

# find the points on the curve

def find_points():
    points = []
    for x in range(0, p):
        y = (x**3 + a*x + b) % p
        points.append((x, y))
    return points

# find the generator points

def find_generator_points():
    points = find_points()
    generator_points = []
    for point in points:
        if point[1] == 0:
            continue
        else:
            generator_points.append(point)
    return generator_points

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

# prime=generate_prime_number()
#check if the number is prime
# if sympy.isprime(prime):
#     print("Prime number is: ",prime)