"""
Author: Yasemin Savaş 54085
Date: 27.10.2022

QUESTION 2

Vigènere cipher

Attack it and find the plaintext and the key. Note that only the letter characters are encrypted.
You have to use frequency analysis. You can use the dictionary provided to you for the letter frequencies.
Output the plaintext and the correct key to a txt file.
Name the file as q2_studentID.txt, first line should be the key and second line should be the plaintext.
You can use any programming language you like.

"""

from helper import letterFrequency, lowercase, uppercase, inv_lowercase
import re
import math
import numpy as np
from queue import Queue

ciphertext = """Fwg atax: P’tx oh li hvabawl jwgvmjs, nw fw tfiapqz lziym, rqgv uuwfpxj wpbk jxlnlz fptf noqe wgw.
Qoifmowl P bdg mg xv qe ntlyk ba bnjh vcf ekghn
izl fq blidb eayz jgzbwx sqwm lgglbtqgy xlip.
Pho fvvs ktf C smf ur ecul ywndxlz uv mzcz xxivw?
Qomdmowl P bgzg, oblzqdxj C swas,
B kyl btm udujs dcbfm vn yg eazl, pqzx,
oblzq Q’ow mwmzb lg ghvk gxslz, emamwx apqu, wwmazagxv nomy bhlustk.”
Ghm qvv’f nbfx h vqe vgoubdg, pgh’a nuvw shvbtmk kbvzq.
Baam jqfg pafs ixetqm wcdanw svc.
Kwn’df dixs mzy ziym llllmfa, zjid wxl
bf nom eifw hlqspuglowall, loyv sztq cu btmlw mhuq phmmla. Kwn’df htiirk yul gx bf noqe kbls. Kwz’b agjl naz mzcuoe mekydpqzx: lblzq’a gg moqb nhj svc, fpxjy’z va zhsx.
Uwi basn fwg’dx ouzbql rgoy tunx zyym, uv mzcz ayied wvzzmk, qib’dq lxknywkmw an ldqzroblzq qg lbl eazev."""

K = range(0, 26)  # the key space


#  Vigenere encryption
def vigenere_encryption(plaintext, key):

    ciphertext = ""
    plaintext_updated = ''.join(e for e in plaintext if e.isalnum())

    for i in range(0, len(plaintext_updated)):
        element = plaintext_updated[i]
        if element.lower() in letterFrequency.keys():
            cipher_element = (lowercase[element.lower()] + lowercase[key[i % len(key)].lower()]) % 26
            encrypted_letter = inv_lowercase[cipher_element]
            ciphertext += encrypted_letter
        else:
            ciphertext += element

    return ciphertext


#  Vigenere decryption
def vigenere_decryption(ciphertext, key):

    plaintext = ""
    ciphertext_updated = ''.join(e for e in ciphertext if e.isalnum())

    for i in range(0, len(ciphertext_updated)):
        element = ciphertext_updated[i]
        if element.lower() in letterFrequency.keys():
            plain_element = (lowercase[element.lower()] - lowercase[key[i % len(key)].lower()]) % 26
            decrypted_letter = inv_lowercase[plain_element]
            plaintext += decrypted_letter
        else:
            plaintext += element

    return plaintext


#  Shift decryption from the first question
def shift_cipher_dec(ciphertext, key):
    plaintext = ''
    ciphertext_updated = ''.join(e for e in ciphertext if e.isalnum())

    for letter in ciphertext_updated:
        if letter.lower() in letterFrequency.keys():
            decrypted_int = (lowercase[letter.lower()] - key) % 26
            decrypted_letter = inv_lowercase[decrypted_int]
            plaintext += decrypted_letter
        else:
            plaintext += letter
    return plaintext


# This function finds the recurring words in a ciphertext
def find_recurring_words(ciphertext):
    no_punctuation_ciphertext = re.sub(r'[^\w\s]', '', ciphertext)
    cipher_array = list(no_punctuation_ciphertext.split())
    merged_ciphertext = ""

    for element in no_punctuation_ciphertext:
        if element in lowercase.keys() or uppercase.keys():
            merged_ciphertext += element

    merged_ciphertext = merged_ciphertext.replace(" ", "")
    merged_ciphertext = merged_ciphertext.replace("\n", "")
    unique_words = set(cipher_array)

    recurring_words = {}
    for word in unique_words:
        if cipher_array.count(word) > 1:
            recurring_words[word] = cipher_array.count(word)

    return merged_ciphertext, recurring_words, cipher_array


# This function finds the recurring words' indexes in a given ciphertext
def find_recurring_word_placements(ciphertext):

    index_dictionary = {}
    merged_ciphertext, recurring_words, cipher_array = find_recurring_words(ciphertext)

    for element in cipher_array:
        if element in recurring_words.keys():
            index_dictionary[element] = [index for index, el in enumerate(cipher_array) if el == element]

    return index_dictionary, merged_ciphertext, recurring_words, cipher_array


def find_key_length_kasiski(ciphertext):

    index_dictionary, merged_ciphertext, recurring_words, cipher_array = find_recurring_word_placements(ciphertext)

    distances = []
    for element, indexes in index_dictionary.items():
        substring = ""
        for word in cipher_array[indexes[0]+1:indexes[1]+1]:
            substring += word
        distances.append(len(substring))

    gcd_list = []
    key_length = 0
    for index in range(0, len(distances)-1):
        gcd_list.append(math.gcd(distances[index], distances[index+1]))  # pair-wise greatest common divisors
        key_length = np.min(gcd_list)

    print("Key length:", key_length)
    return key_length, index_dictionary, merged_ciphertext, recurring_words, cipher_array, gcd_list


# Given the ciphertext and the key space, this function finds the key and decrypts the ciphertext
def find_cipher_key(ciphertext, K):

    ciphertext_updated = ''.join(e for e in ciphertext if e.isalnum())
    differences = []
    sum = 0

    for key in K:
        possible_decryption = shift_cipher_dec(ciphertext_updated, key)
        for letter in list(possible_decryption):
            if letter in letterFrequency.keys():
                probability = (1/26) * (letterFrequency[letter] / len(ciphertext_updated))
                sum += probability

        differences.append(sum)
        sum = 0

    true_key = np.where(differences == np.max(differences))[0][0]
    return differences, true_key


# Given a ciphertext and the key length, this function finds the key and decrypts the ciphertext
def vigenere_attack(ciphertext, K):

    key_length, index_dictionary, merged_ciphertext, recurring_words, cipher_array, gcd_list = find_key_length_kasiski(ciphertext)
    true_key = ""

    for block_number in range(0, key_length):
        block = ""
        for i in range(0+block_number, len(merged_ciphertext), key_length):
            block += merged_ciphertext[i]

        differences, index = find_cipher_key(block, K)
        true_key += inv_lowercase[index]

    return true_key


def add_punctuation_back():

    true_key = vigenere_attack(ciphertext, K)
    decryption = vigenere_decryption(ciphertext, true_key)

    punctuation = Queue()
    for character in ciphertext:
        punctuation.put(character)

    dec_el = Queue()
    for character in decryption:
        dec_el.put(character)

    final_dec = ""
    while dec_el.qsize() > 0:
        punc = punctuation.get()
        if punc.lower() in letterFrequency.keys():
            dec = dec_el.get()
            final_dec += dec
        else:
            final_dec += punc

    with open('q2_54085.txt', 'w') as f:
        f.write(f"KEY: {true_key}")
        f.write("\n")
        f.write(f"PLAINTEXT: {final_dec}")

    f.close()

add_punctuation_back()
