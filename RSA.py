import random

author_name = "Aditya Kumar Gupta"
author_roll_no = "2018013"


def get_signature(m, pk):
    d, n = pk
    client_signature_list = [(ord(i)**d) % n for i in m]
    return client_signature_list


def verify_signature(signatue, pk, message):
    e, n = pk
    message_prime = [chr(((i**e) % n)) for i in signatue]
    message_prime_str = ""
    message_str = ""
    message_prime_str = message_prime_str.join(message_prime)                   # message_prime_str (M')
    message_str = message_str.join(message)                                     # message_str (M)

    if message_prime == message:
        print("Intermediate Verification Code: ", message_prime_str)                
        return True
    return False


def gcd(a, b):
    """
    Euclid's algorithm for determining the greatest common divisor
    """
    while b != 0:
        a, b = b, a % b
    return a


def modInverse(a, m):
    """
        Euclid's extended algorithm for finding the modular multiplicative inverse of two numbers
    """
    m0 = m
    y = 0
    x = 1

    if (m == 1):
        return 0

    while (a > 1):

        # q is quotient
        q = a // m

        t = m

        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y

        # Update x and y
        y = x - q * y
        x = t

    # Make x positive
    if (x < 0):
        x = x + m0

    return x


def is_prime(number):
    """
    check if the number is prime.
    """
    if number == 2:
        return True
    if number < 2 or number % 2 == 0:
        return False
    for n in range(3, int(number**0.5)+2, 2):
        if number % n == 0:
            return False
    return True


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    #n = pq
    n = p * q

    #calculating phi of n
    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(of n) are coprime
    e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    #Use modular inverse function to generate the private key
    d = modInverse(e, phi)
    
    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def rsa_encrypt(pk, plaintext):
    #Unpack the key into it's components
    key, n = pk
    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(ord(char) ** key) % n for char in plaintext]
    return cipher

def rsa_decrypt(pk, ciphertext):
    #Unpack the key into its components
    key, n = pk
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** key) % n) for char in ciphertext]
    return plain
    