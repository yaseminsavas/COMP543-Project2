# COMP543 Project 2
# Author: Yasemin Savas 54085
# Date: 20.12.2022

# Libraries
import random
import math
import os
from time import sleep
import time


# helper function for ascii conversion
def ascii_conversion(text):
    ascii_txt = []
    for character in text:
        ascii_char = str(ord(character))
        ascii_txt.append(ascii_char)
    return ascii_txt


# helper function for a prime number selection using the Miller-Robin primality test.
# I took it from this website: https://rosettacode.org/wiki/Miller–Rabin_primality_test
def primality_check(n):
    """
    Miller-Rabin primality test.

    A return value of False means n is certainly not prime. A return value of
    True means n is very likely a prime.
    """
    if n != int(n):
        return False
    n = int(n)
    # Miller-Rabin test for prime
    if n == 0 or n == 1 or n == 4 or n == 6 or n == 8 or n == 9:
        return False

    if n == 2 or n == 3 or n == 5 or n == 7:
        return True
    s = 0
    d = n - 1
    while d % 2 == 0:
        d >>= 1
        s += 1
    assert (2 ** s * d == n - 1)

    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2 ** i * d, n) == n - 1:
                return False
        return True

    for i in range(8):  # number of trials
        a = random.randrange(2, n)
        if trial_composite(a):
            return False

    return True


# helper function for cyclic group generator (found online)
def cyclic_generator(n):
    results = []
    for a in set(range(1, n)):
        g = set()
        for x in set(range(1, n)):
            g.add((a**x) % n)
        if g == set(range(1, n)):
            results.append(a)
    return results


# Public key generator (as well as the private key of one side)
def elgamal_key_generator():

    # 160 bits lucky primes
    a, b = random.randint(2 ** 1023, 2 ** 1024 - 1), random.randint(2 ** 1023, 2 ** 1024 - 1)
    while not primality_check(a) or primality_check(b):
        a, b = random.randint(2 ** 1023, 2 ** 1024 - 1), random.randint(2 ** 1023, 2 ** 1024 - 1)

    q = a * b  # a very large prime
    q = 79  # I tried a really small prime number for simplicity
    b = random.randint(2, q)
    g = random.randint(2, q)

    while math.gcd(b, g) != 1:
        b = random.randint(2, q)
        g = random.randint(2, q)
        if math.gcd(b, g) == 1:
            break

    F_q = cyclic_generator(q)  # TODO: NEED TO FIX THIS...
    h = pow(g, b)
    public_key = (F_q, h, q, g)

    # Retaining private key (Bob)
    with open('private_key_bob.txt', 'w') as f:
        f.write(str(b))
        f.close()

    print("PUBLIC KEY IS GENERATED...")
    return public_key


# Giving the public key, the other end generates their own private key
def other_side_key_generator():
    with open('server.txt', 'r') as f:
        lines = f.readlines()

    F_q, h, q, g = lines[0][2:], int(lines[1][2:]), int(lines[2][2:]), int(lines[3][2:])
    F_updated = F_q[1:-2].split(", ")
    F_int = []
    for i in F_updated:
        F_int.append(int(i))

    k = random.choice(F_int)

    while math.gcd(k, g) != 1:
        k = random.choice(F_int)
        if math.gcd(k, g) == 1:
            break

    # Retaining private key (Alice)
    with open('private_key_alice.txt', 'w') as f:
        f.write(str(k))
        f.close()

    # deleting the server contents after obtaining the public key contents
    open('server.txt', 'w').close()
    print("OTHER END GENERATED THEIR PRIVATE KEY AND THE SERVER IS CLEANED...")


# ElGamal Encryption Function
def elgamal_encryption(public_key, plaintext):

    # Obtaining private key (Alice)
    F_q, h, q, g = public_key
    with open('private_key_alice.txt', 'r') as f:
        k = int(f.readlines()[0])
        f.close()

    p = pow(g, k)
    s = pow(h, k)
    ascii_plaintext = list(ascii_conversion(plaintext))
    ciphertext = []

    for i in ascii_plaintext:
        ciphertext.append(str((s * int(i))))

    return p, ciphertext


# ElGamal Decryption Function
def elgamal_decryption(p, ciphertext):

    with open('private_key_bob.txt', 'r') as f:
        private_key = int(f.readlines()[0])
        f.close()

    s_ = pow(p, private_key)
    plaintext = []

    for i in ciphertext:
        plaintext.append(chr(int(int(i) / s_)))
    return plaintext


# Write public key and ciphertext to the server.txt
def write_to_server(public_key, ciphertext, p):

    msg_length = len(ciphertext)

    cipher = ""
    for i in range(0, msg_length):
        if i < msg_length - 1:
            cipher += str(ciphertext[i]) + ","
        else:
            cipher += str(ciphertext[i])

    F = str("F:" + str(public_key[0]))
    H = str("H:" + str(public_key[1]))
    Q = str("Q:" + str(public_key[2]))
    G = str("G:" + str(public_key[3]))
    C = str("C:" + str(cipher))
    P = str("p:" + str(p))

    f = open("server.txt", "w")
    f.write(F + "\n")
    f.write(H + "\n")
    f.write(Q + "\n")
    f.write(G + "\n")
    f.write(C + "\n")
    f.write(P)
    f.close()


def server_initialization():
    print("COMMUNICATION STARTED, GENERATING THE SERVER...")

    try:
        with open('server.txt', 'x') as f:
            f.close()
    except:
        print("SERVER ALREADY EXISTS.")

    public_key = elgamal_key_generator()
    F, H, Q, G = str("F:" + str(public_key[0])), str("H:" + str(public_key[1])), \
                 str("Q:" + str(public_key[2])), str("G:" + str(public_key[3]))

    f = open("server.txt", "w")
    f.write(F + "\n")
    f.write(H + "\n")
    f.write(Q + "\n")
    f.write(G + "\n")
    f.close()
    print("PUBLIC KEY SENT TO THE OTHER END...")
    return public_key


public_key = server_initialization()
other_side_key_generator()

chat_count = 0
sleep(5)  # waiting 5 seconds for input
while True:
    # sending the first message in an existing server
    if os.path.getsize('server.txt') == 0:

        print("NO INCOMING MESSAGES...")
        plaintext = input("SEND A MESSAGE: ")
        p, ciphertext = elgamal_encryption(public_key, plaintext)

        ctext = ""
        for i in ciphertext:
            ctext += str(i)
        write_to_server(public_key, ciphertext, p)
        chat_count += 1

    # communication in later steps
    elif os.path.getsize('server.txt') > 0:

        with open('server.txt', 'r') as f:
            lines = f.readlines()

        F, H, Q, G, ciphertext, p = lines[0][2:], lines[1][2:], lines[2][2:], lines[3][2:], lines[4][2:], lines[5][2:]
        ciphertext = ciphertext.split(",")
        plaintext = elgamal_decryption(int(p), ciphertext)

        str_ptext = ""
        for i in plaintext:
            str_ptext += i
        print("INCOMING MESSAGE:", ascii(str_ptext))

        # deleting the server contents after decrypting an incoming message.
        open('server.txt', 'w').close()

        plaintext = input("ANSWER THE MESSAGE: ")

        F_updated = F[1:-2].split(", ")
        F_int = []
        for i in F_updated:
            F_int.append(int(i))

        public_key = (F_int, int(H), int(Q), int(G))
        p, ciphertext = elgamal_encryption(public_key, plaintext)

        ctext = ""
        for i in ciphertext:
            ctext += str(i)

        write_to_server(public_key, ciphertext, p)

    print("MESSAGE SENT...")
    print("CHECKING THE SERVER FOR AN INCOMING MESSAGE...")
    sleep(5)
