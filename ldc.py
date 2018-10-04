# Justin Huynh
# 7745112
# CSI4108 Assignment 2 Question 2

import random

s_box = {'0':'E',
         '1':'4',
         '2':'D',
         '3':'1',
         '4':'2',
         '5':'F',
         '6':'B',
         '7':'8',
         '8':'3',
         '9':'A',
         'A':'6',
         'B':'C',
         'C':'5',
         'D':'9',
         'E':'0',
         'F':'7'
         }


perm = [0, 4, 8, 12,
       1, 5, 9, 13,
       2, 6, 10, 14,
       3, 7, 11, 15]


def convert_binary(hex_key):
    scale = 16  # Hex
    num_of_bits = 16
    binary_string = ""
    count = 1

    for hex_char in hex_key:
        i = bin(int(hex_char, scale))[2:].zfill(num_of_bits)
        binary_string += i

    return binary_string


def apply_sbox(text):
    out = ""
    for i in text:
        out += s_box[i]
    return out


def permute(original, permutation):
    return [original[i] for i in permutation]


def generate_plaintext():
    # Generate 10 000 16-bit plaintext values
    plaintext = {}
    for i in range(0, 10000):
        plaintext[str(i).zfill(16)] = ""
    return plaintext


def encrypt(key):
    plaintext_cipher_map = generate_plaintext()

    for plain, cipher in plaintext_cipher_map.items():
        for i in range(0,4):
            cipher = str(int(convert_binary(plain)) ^ int(convert_binary(key)))
            cipher = apply_sbox(cipher)
            cipher = permute(cipher, perm)

    return plaintext_cipher_map

