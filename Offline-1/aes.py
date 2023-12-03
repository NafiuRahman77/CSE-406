# AES encryption algorithm

import sys
from BitVector import *
import random
import time

# S-box
sbox = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

# Inverse S-box
inv_sbox = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]]

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"),
     BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"),
     BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"),
     BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"),
     BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"),
     BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"),
     BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"),
     BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"),
     BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

AES_modulus = BitVector(bitstring='100011011')

# rcon
rcon = [
    ["01", "00", "00", "00"],
    ["02", "00", "00", "00"],
    ["04", "00", "00", "00"],
    ["08", "00", "00", "00"],
    ["10", "00", "00", "00"],
    ["20", "00", "00", "00"],
    ["40", "00", "00", "00"],
    ["80", "00", "00", "00"],
    ["1b", "00", "00", "00"],
    ["36", "00", "00", "00"]
]


def key_scheduling(key, ishex):

    keys = []
    if ishex == False:
        round_key = key.encode('utf-8').hex()
    else:
        round_key = key
    # keep the key in a 4 by 4 2d array
    round_key = [[round_key[i:i+2]
                  for i in range(j, len(round_key), 8)] for j in range(0, 8, 2)]
    keys.append(round_key)

    time.sleep(0.0000000000000000000000000000000000000001)
    for round in range(1, 11):

        # schedule my round key
        w = [[round_key[j][i] for j in range(4)] for i in range(4)]
        # circular left shift of w[3]
        g = w[3][1:] + w[3][:1]

        # substitute bytes of w[3]
        for j in range(4):
            g[j] = hex(sbox[int(g[j][0], 16)]
                       [int(g[j][1], 16)])[2:].zfill(2)

        # xor w[3] with rcon[i]
        for j in range(4):
            g[j] = hex(int(g[j], 16) ^ int(rcon[round-1][j], 16))[2:].zfill(2)

        # iterate over all rows of w
        for j in range(4):

            # xor w[j] with g if j = 0
            if j == 0:
                for k in range(4):
                    w[j][k] = hex(int(w[j][k], 16) ^ int(g[k], 16))[
                        2:].zfill(2)
            else:
                # xor w[j] with w[j-1]
                for k in range(4):
                    w[j][k] = hex(int(w[j][k], 16) ^ int(
                        w[j-1][k], 16))[2:].zfill(2)

        round_key = [[w[j][i] for j in range(4)] for i in range(4)]
        keys.append(round_key)

    return keys


def aes_encrypt_for_one_chunk(chunk, key, ishex):
    # round 0
    # convert chunk to hex
    # chunk = chunk.encode('utf-8').hex()

    # keep the chunk in a 4 by 4 2d array
    state = [[chunk[i:i+2]
              for i in range(j, len(chunk), 8)] for j in range(0, 8, 2)]

    keys = key_scheduling(key, ishex)

    round_key = keys[0]
    # xor the state with the round key
    for i in range(4):
        for j in range(4):
            state[i][j] = hex(int(state[i][j], 16) ^ int(
                round_key[i][j], 16))[2:].zfill(2)

    for round in range(1, 11):
        round_key = keys[round]
        # substitute bytes
        for j in range(4):
            for k in range(4):
                state[j][k] = hex(sbox[int(state[j][k][0], 16)]
                                  [int(state[j][k][1], 16)])[2:].zfill(2)
        # shift rows
        state[1:] = [state[j][j:] + state[j][:j] for j in range(1, 4)]
        # Convert each string to BitVector
        matrix = [
            [BitVector(hexstring=element) for element in row]
            for row in state
        ]

        if round != 10:
            # mix columns using Bitvector library
            temp_ = []
            for _ in range(len(matrix)):
                temp_.append([BitVector(intVal=0, size=8)] * len(matrix[0]))
            for p in range(0, len(matrix)):
                for j in range(0, len(matrix[0])):
                    for k in range(0, len(matrix)):
                        temp_[p][j] = temp_[p][j] ^ (
                            Mixer[p][k].gf_multiply_modular(matrix[k][j], AES_modulus, 8))

            # copy temp_ values to state
            for i in range(len(matrix)):
                for j in range(len(matrix[0])):
                    state[i][j] = temp_[i][j]
            # Convert each BitVector to hex string
            state = [[element.get_bitvector_in_hex() for element in row]
                     for row in state]

        # xor the state with the round key
        for i in range(4):
            for j in range(4):
                state[i][j] = hex(int(state[i][j], 16) ^ int(
                    round_key[i][j], 16))[2:].zfill(2)

        # print("state",state)
    # cipher_text_chunk= ''.join(chr(int(state[j][i],16)) for i in range(4) for j in range(4)) # ei line ta tomar jonno important

    return state


# aes encyption function

def aes_encryption(plain_text, key, ishex, iv_g):
    # convert plain_text to a chunks array with 16 characters in each chunk
    chunk_size = 16
    chunks = [plain_text[i:i + chunk_size].ljust(chunk_size)
              for i in range(0, len(plain_text), chunk_size)]
    # cbc mode
    iv = iv_g

    # print("chunks",chunks)
    cipher_text = ""
    cipher_hex = ""
    for chunk in chunks:
        # print("chunk",chunk)
        # xor chunk with iv
        c = chunk.encode('utf-8').hex()
        c = BitVector(hexstring=c)
        c = c ^ BitVector(hexstring=iv)
        c = c.get_bitvector_in_hex()

        cipher_state = aes_encrypt_for_one_chunk(c, key, ishex)
        cipher_text_chunk = ''.join(
            chr(int(cipher_state[j][i], 16)) for i in range(4) for j in range(4))
        # create a variable that takes the cipher_state and convert it to string
        cipher_hex_chunk = ''.join(
            cipher_state[j][i] for i in range(4) for j in range(4))
        cipher_text += cipher_text_chunk
        cipher_hex += cipher_hex_chunk
        # set iv to cipher_text_chunk
        iv = cipher_hex_chunk

    # print("cipher_text",cipher_text)
    return cipher_text, cipher_hex


# aes decryption function
def aes_decryption(cipher_hex_text, key, ishex, iv_g):
    # print("cipher_hex_text", cipher_hex_text)
    # print("len", len(cipher_hex_text))
    # convert cipher_hex_text to a chunks array with 32 hex values in each chunk
    chunk_size = 32
    chunks = [cipher_hex_text[i:i + chunk_size].ljust(chunk_size)
              for i in range(0, len(cipher_hex_text), chunk_size)]
    decrypted_text = ""

    iv = iv_g

    for chunk in chunks:
        # print("dchunk",chunk)
        decrypted_state = aes_decrypt_for_one_chunk(chunk, key, ishex)

        decrypted_hex = ''.join(
            decrypted_state[j][i] for i in range(4) for j in range(4))
        # print("decrypted_hex",decrypted_hex)
        # xor decrypted_hex with iv
        d = BitVector(hexstring=decrypted_hex)
        d = d ^ BitVector(hexstring=iv)
        d = d.get_bitvector_in_hex()
        # convert decrypted_hex back to string taking two hex values at a time
        d = ''.join(chr(int(d[i:i+2], 16))
                    for i in range(0, len(decrypted_hex), 2))
        # set iv to cipher_text_chunk
        iv = chunk
        decrypted_text += d
    # print("decrypted_text",decrypted_text)
    return decrypted_text


def aes_decrypt_for_one_chunk(chunk, key, ishex):

    # round 0

    # keep the chunk in a 4 by 4 2d array
    state = [[chunk[i:i+2]
              for i in range(j, len(chunk), 8)] for j in range(0, 8, 2)]

    # print("state",state)

    keys = key_scheduling(key, ishex)
    # invert the keys array
    keys = keys[::-1]
    round_key = keys[0]
    # xor the state with the round key
    for i in range(4):
        for j in range(4):
            state[i][j] = hex(int(state[i][j], 16) ^ int(
                round_key[i][j], 16))[2:].zfill(2)

    # print("state",state)
    for round in range(1, 11):
        # print("round",round)
        round_key = keys[round]

        # inverse shift rows
        state[1:] = [state[j][-j:] + state[j][:-j] for j in range(1, 4)]
        # print("state",state)

        # inverse substitute bytes
        for j in range(4):
            for k in range(4):
                state[j][k] = hex(inv_sbox[int(state[j][k][0], 16)]
                                  [int(state[j][k][1], 16)])[2:].zfill(2)
        # print("state",state)

        # xor the state with the round key
        for i in range(4):
            for j in range(4):
                state[i][j] = hex(int(state[i][j], 16) ^ int(
                    round_key[i][j], 16))[2:].zfill(2)
        # print("state",state)

        # Convert each string to BitVector
        matrix = [
            [BitVector(hexstring=element) for element in row]
            for row in state
        ]

        if round != 10:
            # mix columns using Bitvector library
            temp_ = []
            for _ in range(len(matrix)):
                temp_.append([BitVector(intVal=0, size=8)] * len(matrix[0]))
            for p in range(0, len(matrix)):
                for j in range(0, len(matrix[0])):
                    for k in range(0, len(matrix)):
                        temp_[p][j] = temp_[p][j] ^ (
                            InvMixer[p][k].gf_multiply_modular(matrix[k][j], AES_modulus, 8))

            # copy temp_ values to state
            for i in range(len(matrix)):
                for j in range(len(matrix[0])):
                    state[i][j] = temp_[i][j]
            # Convert each BitVector to hex string
            state = [[element.get_bitvector_in_hex() for element in row]
                     for row in state]

    # print("state ", state)
    return state


def generate_iv():
    # 128 bit random initialization vector
    iv = BitVector(textstring=''.join(chr(random.randint(0, 0xFF))
                   for i in range(16)))
    # convert iv to hex
    iv = iv.get_bitvector_in_hex()
    # print("iv",iv)
    return iv

# iv_g="01acc50656e8391c3d8924baa00a85d9"
# print("iv_g",iv_g)
# print(len("e674fa77b66e3746164df8073d01651d"))
# res=aes_encryption("Never Gonna Give you up", "e674fa77b66e3746164df8073d01651d", True)
# print(repr(res[0]),res[1])
# print(aes_decryption(res[1],"e674fa77b66e3746164df8073d01651d"))
# s= "That's my Kung Fu"
# d=s.encode('utf-8').hex()
# print(d)
# print d back to string
# print(bytes.fromhex(d).decode('utf-8'))


# res=aes_encryption("Never Gonna Give you up", "af519dd5e58159d466167a94c0316924", True)
# print("chunku",res)
# print(aes_decryption(res[1],"af519dd5e58159d466167a94c0316924", True))

def aes_simulation(plaintext, key , iv):
    print("Key:")
    print("In ASCII:", key)
    print("In Hex:", key.encode('utf-8').hex())
    print()

    # key scheduling time
    start_time = time.time()
    keys = key_scheduling(key, False)

    end_time = time.time()
    print("keys", keys)
    time_key_scheduling = end_time - start_time

    print("Plaintext:")
    print("In ASCII:", plaintext)
    print("In Hex:", plaintext.encode('utf-8').hex())
    print()

    print("Ciphered Text:")
    start_time = time.time()
    ciphertext = aes_encryption(plaintext, key, False, iv)
    end_time = time.time()
    time_encryption = end_time - start_time
    print("In ASCII:", repr(ciphertext[0]))
    print("In Hex:", ' '.join(ciphertext[1][i:i+2] for i in range(0, len(ciphertext[1]), 2)))
    print()

    print("Decrypted Plaintext:")
    start_time = time.time()
    decrypted_text = aes_decryption(ciphertext[1], key, False, iv)
    end_time = time.time()
    time_decryption = end_time - start_time
    print("In ASCII:", decrypted_text)
    decrypted_text = decrypted_text.encode('utf-8').hex()
    print("In Hex:", ' '.join(decrypted_text[i:i+2] for i in range(0, len(decrypted_text), 2)))   
    print()

    print("Key scheduling time:", time_key_scheduling*1000, "ms")
    print("Encryption time:", time_encryption*1000, "ms")
    print("Decryption time:", time_decryption*1000, "ms")


def main():
    iv = generate_iv()
    aes_simulation("Never Gonna Give you up", "BUET CSE19 BATCH", iv )

# if __name__ == "__main__":
#     main()
