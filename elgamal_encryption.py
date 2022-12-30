# COMP543 Project 2
# Author: Yasemin Savas 54085
# Date: 20.12.2022

# Libraries
import random
import math
import os
from time import sleep


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


# Public key generator (as well as the private key of one side)
def elgamal_key_generator():

    q = random.randint(2 ** 1023, 2 ** 1024 - 1)
    while not primality_check(q):
        q = random.randint(2 ** 1023, 2 ** 1024 - 1)

    b = random.randint(2, q)
    generators = [random.randint(2, q)]
    g = random.choice(generators)

    while math.gcd(b, g) != 1:
        b = random.randint(2, q)
        g = random.choice(generators)
        if math.gcd(b, g) == 1:
            break

    h = pow(g, b, q)
    public_key = (h, q, g)

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

    h, q, g = lines[0][2:], int(lines[1][2:]), int(lines[2][2:])

    k = random.randint(2, int(h))

    while math.gcd(k, g) != 1:
        k = random.randint(2, int(h))
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
    h, q, g = public_key
    with open('private_key_alice.txt', 'r') as f:
        k = int(f.readlines()[0])
        f.close()

    p = pow(g, k, q)
    s = pow(h, k, q)
    ascii_plaintext = list(ascii_conversion(plaintext))
    ciphertext = []

    for i in ascii_plaintext:
        ciphertext.append(str((s * int(i))))

    return p, ciphertext


# ElGamal Decryption Function
def elgamal_decryption(p, q, ciphertext):

    with open('private_key_bob.txt', 'r') as f:
        private_key = int(f.readlines()[0])
        f.close()

    s_ = pow(p, private_key, q)
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

    H = str("H:" + str(public_key[0]))
    Q = str("Q:" + str(public_key[1]))
    G = str("G:" + str(public_key[2]))
    C = str("C:" + str(cipher))
    P = str("p:" + str(p))

    f = open("server.txt", "w")
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
    H, Q, G = str("F:" + str(public_key[0])), str("H:" + str(public_key[1])), str("Q:" + str(public_key[2]))

    f = open("server.txt", "w")
    f.write(H + "\n")
    f.write(Q + "\n")
    f.write(G + "\n")
    f.close()
    print("PUBLIC KEY SENT TO THE OTHER END...")
    return public_key


public_key = server_initialization()
other_side_key_generator()

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

    # communication in later steps
    elif os.path.getsize('server.txt') > 0:

        with open('server.txt', 'r') as f:
            lines = f.readlines()

        H, Q, G, ciphertext, p = lines[0][2:], lines[1][2:], lines[2][2:], lines[3][2:], lines[4][2:]
        ciphertext = ciphertext.split(",")
        plaintext = elgamal_decryption(int(p), int(Q), ciphertext)

        str_ptext = ""
        for i in plaintext:
            str_ptext += i
        print("INCOMING MESSAGE:", ascii(str_ptext))

        # deleting the server contents after decrypting an incoming message.
        #open('server.txt', 'w').close()

        plaintext = input("ANSWER THE MESSAGE: ")

        public_key = (int(H), int(Q), int(G))
        p, ciphertext = elgamal_encryption(public_key, plaintext)

        ctext = ""
        for i in ciphertext:
            ctext += str(i)

        write_to_server(public_key, ciphertext, p)

    print("MESSAGE SENT...")
    print("CHECKING THE SERVER FOR AN INCOMING MESSAGE...")
    sleep(5)