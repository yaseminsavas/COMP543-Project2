# COMP543 Project 2
# Author: Yasemin Savas 54085
# Date: 20.12.2022

# Libraries
import random
import math
import os
from time import sleep
from math import factorial


# helper function for ascii conversion
def ascii_conversion(text):
    ascii_txt = []
    for character in text:
        ascii_char = str(ord(character))
        ascii_txt.append(ascii_char)
    return ascii_txt


# helper function for prime number selection
def random_prime_selector(p, q):
    primes = [i for i in range(p, q) if factorial(i - 1) % i == i - 1]
    n = random.choice(primes)
    return n


# helper function for cyclic group generator (found online)
def cyclic_generator(n):
    s = set(range(1, n))
    results = []
    for a in s:
        g = set()
        for x in s:
            g.add((a**x) % n)
        if g == s:
            results.append(a)
    return results


"""
Bob generates public and private keys:
a. Bob chooses a large number q and a cyclic group F_q
b. Bob chooses a random generator g for Fq and an element b such that gcd(b,q) = 1
c. Bob computes h = g^b
d. Bob publishes F, h, q and g, retains b as private key
"""


def elgamal_key_generator():

    q = random_prime_selector(50, 200)
    F_q = cyclic_generator(q)
    b = random.randint(2, q)
    g = random.choice(F_q)

    while math.gcd(b, g) != 1:
        b = random.randint(2, q)
        g = random.choice(F_q)
        if math.gcd(b, g) == 1:
            break

    h = pow(g, b)
    public_key = (F_q, h, q, g)

    # Retaining private key
    private_key_1 = b
    with open('private_key.txt', 'w') as f:
        f.write(str(private_key_1))
        f.close()

    return public_key


"""
2. Alice encrypts the message using Bob’s public key:
a. Alice chooses k from cyclic group F such that gcd(a, q) = 1
b. Alice computes p = g^k and s = h^k= g^(a*b)
c. Alice encrypts M with s
d. Alice publishes (p, M x s) = (gk , M x s)
"""


def elgamal_encryption(public_key, plaintext):

    F_q, h, q, g = public_key
    k = random.choice(F_q)

    while math.gcd(k, g) != 1:
        k = random.choice(F_q)
        if math.gcd(k, g) == 1:
            break

    p = pow(g, k)
    s = pow(h, k)

    ascii_plaintext = list(ascii_conversion(plaintext))

    ciphertext = []
    for i in ascii_plaintext:
        ciphertext.append(str((s * int(i))))

    return p, ciphertext


"""
3. Bob decrypts the message:
a. Bob calculates s’ = p^b = g^ab
b. Bob decrypts M x s with s’ and obtains M.
"""


def elgamal_decryption(p, ciphertext):

    with open('private_key.txt', 'r') as f:
        private_key = int(f.readlines()[0])
        f.close()

    s_ = pow(p, private_key)

    plaintext = []
    for i in ciphertext:
        plaintext.append(chr(int(int(i) / s_)))
    return plaintext


def write_to_server(public_key, ciphertext, p):

    msg_length = len(ciphertext)

    cipher = ""
    for i in range(0, msg_length):
        cipher += str(ciphertext[i]) + ","

    F = str("F:" + str(public_key[0]))
    H = str("H:" + str(public_key[1]))
    Q = str("Q:" + str(public_key[2]))
    G = str("G:" + str(public_key[3]))
    C = str("C:" + ascii(str(cipher)))
    P = str("p:" + str(p))

    f = open("server.txt", "w")
    f.write(F + "\n")
    f.write(H + "\n")
    f.write(Q + "\n")
    f.write(G + "\n")
    f.write(C + "\n")
    f.write(P)
    f.close()


chat_count = 0
while True:

    if os.path.exists("server.txt") is False:
        with open('server.txt', 'x') as f:
            f.close()

    print("CHECKING THE SERVER...")
    sleep(5)

    if os.path.getsize('server.txt') == 0 and chat_count == 0:

        print("NO INCOMING MESSAGES...")
        plaintext = input("SEND A MESSAGE: ")

        public_key = elgamal_key_generator()
        p, ciphertext = elgamal_encryption(public_key, plaintext)

        ctext = ""
        for i in ciphertext:
            ctext += str(i)
        write_to_server(public_key, ciphertext, p)
        chat_count += 1

    else:
        print("CHECKING THE SERVER...")
        sleep(5)
        try:
            with open('server.txt', 'r') as f:
                lines = f.readlines()

            F, H, Q, G, ciphertext, p = lines[0][2:], lines[1][2:], lines[2][2:], lines[3][2:], lines[4][2:], lines[5][2:]

            ciphertext = ciphertext.split(",")[:-1]
            plaintext = elgamal_decryption(int(p), ciphertext)

            str_ptext = ""
            for i in plaintext:
                str_ptext += i
            print("INCOMING MESSAGE:", ascii(str_ptext))
            open('server.txt', 'w').close()

            plaintext = input("ANSWER THE MESSAGE: ")
            p, ciphertext = elgamal_encryption(public_key, plaintext)

            ctext = ""
            for i in ciphertext:
                ctext += str(i)

            write_to_server(public_key, ciphertext, p)

        except:
            print("WAITING FOR AN INCOMING MESSAGE...")
            sleep(5)