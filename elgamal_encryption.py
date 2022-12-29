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


# helper function for prime number selection
# I took it from this website: https://rosettacode.org/wiki/Miller–Rabin_primality_test
def is_Prime(n):
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

    print("FINDING A 1024-BIT PRIME NUMBER...")
    primality = False
    while primality is False:
        q = random.randrange(2**1023+1, 2**1024-1)
        if is_Prime(q):
            primality = True

    print("GENERATING THE CYCLIC GROUP...")
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

    # Retaining private key (Bob)
    with open('private_key_bob.txt', 'w') as f:
        f.write(str(b))
        f.close()

    print("PUBLIC KEY IS GENERATED...")
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

    # Retaining private key (Alice)
    with open('private_key_alice.txt', 'w') as f:
        f.write(str(k))
        f.close()

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

    with open('private_key_bob.txt', 'r') as f:
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


chat_count = 0
while True:

    # initializing the chat server, sending the first msg
    if os.path.exists("server.txt") is False and chat_count == 0:
        print("COMMUNICATION STARTED, GENERATING THE SERVER...")

        public_key = elgamal_key_generator()
        with open('server.txt', 'x') as f:
            f.close()

        plaintext = input("SEND A MESSAGE: ")
        p, ciphertext = elgamal_encryption(public_key, plaintext)

        ctext = ""
        for i in ciphertext:
            ctext += str(i)
        write_to_server(public_key, ciphertext, p)
        chat_count += 1
        print("MESSAGE SENT...")

        print("CHECKING THE SERVER FOR AN INCOMING MESSAGE...")
        sleep(5)

    # sending the first msg in an existing server
    elif os.path.exists("server.txt") is True and os.path.getsize('server.txt') == 0 and chat_count == 0:

        print("NO INCOMING MESSAGES...")
        plaintext = input("SEND A MESSAGE: ")
        public_key = elgamal_key_generator()
        p, ciphertext = elgamal_encryption(public_key, plaintext)

        ctext = ""
        for i in ciphertext:
            ctext += str(i)
        write_to_server(public_key, ciphertext, p)
        chat_count += 1
        print("MESSAGE SENT...")

        print("CHECKING THE SERVER FOR AN INCOMING MESSAGE...")
        sleep(5)

    # communication in later steps
    elif os.path.exists("server.txt") is True and os.path.getsize('server.txt') > 0:

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

        print("CHECKING THE SERVER FOR AN INCOMING MESSAGE...")
        sleep(5)

    elif os.path.exists("server.txt") is True and os.path.getsize('server.txt') == 0 and chat_count > 0:

        print("NO INCOMING MESSAGES...")
        plaintext = input("SEND A MESSAGE: ")
        try:
            p, ciphertext = elgamal_encryption(public_key, plaintext)
        except:
            public_key = elgamal_key_generator()
            p, ciphertext = elgamal_encryption(public_key, plaintext)

        ctext = ""
        for i in ciphertext:
            ctext += str(i)
        write_to_server(public_key, ciphertext, p)
        chat_count += 1
        print("MESSAGE SENT...")

        print("CHECKING THE SERVER FOR AN INCOMING MESSAGE...")
        sleep(5)

    else:
        print("AN ERROR OCCURRED. DELETE THE SERVER FILE & RESTART")
        break