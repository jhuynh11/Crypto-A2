# Justin Huynh
# 7745112
# CSI4108 Assignment 2 Question 2
# To perform the attack, start a python interpreter and do
#   from q2 import *
#   attack()
# This will output the subkey with maximum bias and output all bias calculations
# to the file 'bias.csv'

import csv
import pandas as pd

key = "AEA5"  # The same key is used for each round of key mixing

s_box = {'0': 'E',
         '1': '4',
         '2': 'D',
         '3': '1',
         '4': '2',
         '5': 'F',
         '6': 'B',
         '7': '8',
         '8': '3',
         '9': 'A',
         'A': '6',
         'B': 'C',
         'C': '5',
         'D': '9',
         'E': '0',
         'F': '7'
         }

inv_s_box = {v: k for k, v in s_box.items()}  # Inverted s-box mapping

perm = [0, 4, 8, 12,
        1, 5, 9, 13,
        2, 6, 10, 14,
        3, 7, 11, 15]


def convert_binary(hex_key):
    scale = 16  # Hex
    num_of_bits = 4
    binary_string = ""

    for hex_char in hex_key:
        i = bin(int(hex_char, scale))[2:].zfill(num_of_bits)
        binary_string += i

    binary_string = binary_string.zfill(16) # Add this?
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
        plaintext[str(i)] = ""
        # plaintext[str(i).zfill(16)] = ""
    return plaintext


def encrypt(key):
    """
    Encrypts 10 000 plaintext to cipher text values. This algorithm has 4 rounds of:
    A) Key Mixing
    B) S-Box substitution
    C) Permutation
    :param key: 16 bit hex key used to encrypt plaintext
    :return: Dictionary of 10 000 plaintext cipher text pairs
    """
    plaintext_cipher = generate_plaintext()

    for plain in plaintext_cipher:
        # Initial XOR
        # plaintext_cipher[plain] = format((int(plain, 16)) ^ (int(key, 16)), 'X')
        plaintext_cipher[plain] = format(int(plain) ^ int(key, 16), 'X')
        for i in range(0, 4):
            # Apply S-box substitutions
            plaintext_cipher[plain] = apply_sbox(plaintext_cipher[plain])

            # Permute output of S-box
            plaintext_cipher[plain] = ''.join(permute(convert_binary(plaintext_cipher[plain]), perm))
            plaintext_cipher[plain] = format(int(plaintext_cipher[plain], 2), 'X')

            # XOR with Key
            plaintext_cipher[plain] = format((int(plaintext_cipher[plain], 16)) ^ (int(key, 16)), 'X').zfill(4)
    return plaintext_cipher


def output_plain_cipher_pairs():
    """
    Prints plaintext ciphertext pairs into out_hex.csv
    """
    plain_cipher = encrypt(key)
    w = csv.writer(open("out_hex.csv", "w"))
    for plain, cipher in plain_cipher.items():
        w.writerow([plain, cipher])


def attack():
    """
    Generates 10 000 plaintext-ciphertext pairs and calculates the bias for each
    possible partial subkey from 0 - 255.
    :return: Prints the subkey with maximum bias and outputs all results into file "bias.csv"
    """
    plain_cipher_hex = encrypt(key)
    plain_cipher_bin = {}
    d = {'partial_subkey':[], 'count': [], 'bias':[]}

    # Convert the plaintext cipher pairs into binary
    for plain, cipher in plain_cipher_hex.items():
        plain_cipher_bin[convert_binary(plain)] = convert_binary(cipher)

    # Test 256 Partial Subkeys
    for i in range(0, 256):
        count = 0
        for plain, cipher in plain_cipher_bin.items():
            u4_5to8 = get_U(subkey=format(i, 'X').zfill(2)[0],  # EX: F8 -> F
                            cipher=cipher[4:8])
            u4_13to16 = get_U(subkey=format(i, 'X').zfill(2)[1],  # EX: F8 -> 8
                              cipher=cipher[12:])

            u46 = int(u4_5to8[1])
            u48 = int(u4_5to8[3])
            u414 = int(u4_13to16[1])
            u416 = int(u4_13to16[3])

            p5 = int(plain[4])
            p7 = int(plain[6])
            p8 = int(plain[8])

            if u46 ^ u48 ^ u414 ^ u416 ^ p5 ^ p7 ^ p8 == 0:
                count += 1

        d['partial_subkey'].append(format(i,'X').zfill(2))
        d['count'].append(count)
        d['bias'].append(abs(count - 5000) / 10000)

    df = pd.DataFrame(d)
    print("SUBKEY WITH MAXIMUM BIAS: ")
    print(df.loc[df['bias'].idxmax()])
    df.to_csv('bias.csv')

    # Print the binary plaintext cipher text keys into a CSV file
    # w = csv.writer(open("out_bin.csv", "w"))
    # for plain, cipher in plain_cipher_bin.items():
    #     w.writerow([plain, cipher])


def get_U(subkey, cipher):
    """
    Gets the input to the 4th round of S-Box substitutions
    :param subkey: 4 bit Hex value in range (0000, F)
    :param cipher: Corresponding cipher text for the plain text
    :return: Binary string representing the 4th round input to S Box
    """
    # Convert cipher to hex
    hex_cipher = hex(int(cipher, 2))

    # XOR with partial subkey
    r = format(int(subkey, 16) ^ (int(hex_cipher, 16)), 'X')

    # Reverse S-Box
    out = ""
    for i in str(r):
        out += inv_s_box[i]

    # Return binary
    return convert_binary(out)[12:]  # This is a 16 bit binary, only want last 4 bits
