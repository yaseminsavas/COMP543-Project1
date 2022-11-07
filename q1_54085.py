"""
Author: Yasemin Savaş 54085
Date: 27.10.2022

QUESTION 1

Write a program to try all possible shifts on the ciphertext below, select the right one and output the plaintext
and the correct key to a txt file.
Name the file as q1_studentID.txt, first line should be the key and second line should be the plaintext.
You can use any programming language you like.
"""

import numpy as np
from collections import Counter
from helper import letterFrequency, lowercase, inv_lowercase

K = range(0, 26)  # the key space
ciphertext = """kyivv izexj wfi kyv vcmve-bzexj leuvi kyv jbp, jvmve wfi kyv unriwcfiuj ze kyvzi yrccj fw jkfev, ezev wfi dfikrc dve uffdvu kf uzv, fev wfi kyv urib cfiu fe yzj urib kyifev; ze kyv creu fw dfiufi nyviv kyv jyrufnj czv. fev izex kf ilcv kyvd rcc, fev izex kf wzeu kyvd, fev izex kf sizex kyvd rcc, reu ze kyv uribevjj szeu kyvd; ze kyv creu fw dfiufi nyviv kyv jyrufnj czv."""
optimal_probability = 0.065


# This is the shift cipher's encryption algorithm
def shift_cipher_enc(plaintext, key):
    ciphertext = ''
    for letter in plaintext:
        if letter in letterFrequency.keys():
            encrypted_int = (lowercase[letter.lower()] + key) % 26
            encrypted_letter = inv_lowercase[encrypted_int]
            ciphertext += encrypted_letter
        else:
            ciphertext += letter
    return ciphertext


# This is the shift cipher's decryption algorithm
def shift_cipher_dec(ciphertext, key):
    plaintext = ''
    for letter in ciphertext:
        if letter in letterFrequency.keys():
            decrypted_int = (lowercase[letter.lower()] - key) % 26
            decrypted_letter = inv_lowercase[decrypted_int]
            plaintext += decrypted_letter
        else:
            plaintext += letter
    return plaintext


# This finds the ciphertext letter frequencies
def frequencies(ciphertext):
    ciphertext_updated = ''.join(e for e in ciphertext if e.isalnum())
    ciphertext_frequency_dict = Counter(ciphertext_updated)
    return ciphertext_frequency_dict, ciphertext_updated


# Given the ciphertext and the key space, this function finds the key and decrypts the ciphertext
def find_cipher_key(ciphertext, K):

    ciphertext_frequency_dict, ciphertext_updated = frequencies(ciphertext)
    differences = []
    sum = 0

    for key in K:
        possible_decryption = shift_cipher_dec(ciphertext, key)
        for letter in list(possible_decryption):
            if letter in letterFrequency.keys():
                probability = (1/26) * (letterFrequency[letter] / len(ciphertext_updated))
                sum += probability

        differences.append(sum)
        sum = 0

    true_key = np.where(differences == np.max(differences))[0][0]
    decryption = shift_cipher_dec(ciphertext, true_key)

    return differences, true_key, decryption


differences, true_key, decryption = find_cipher_key(ciphertext, K)

with open('q1_54085.txt', 'w') as f:
    f.write(f"KEY: {true_key}")
    f.write("\n")
    f.write(f"PLAINTEXT: {decryption}")

f.close()











