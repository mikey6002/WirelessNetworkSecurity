import random
import math

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        # Ensure that n is odd
        n |= (1 << bits - 1) | 1  # Set the most significant bit and least significant bit
        if is_prime(n):
            return n

def mod_inverse(a, m):
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keypair(bits):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537  # Commonly used value for e
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def mod_pow(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def encrypt(public_key, plaintext):
    e, n = public_key
    return [mod_pow(ord(char), e, n) for char in plaintext]

def decrypt(private_key, ciphertext):
    d, n = private_key
    return ''.join([chr(mod_pow(char, d, n)) for char in ciphertext])

# Example usage
bits = 1024
public_key, private_key = generate_keypair(bits)
message = "Hello, RSA!"
encrypted_msg = encrypt(public_key, message)
decrypted_msg = decrypt(private_key, encrypted_msg)

print(f"Original message: {message}")
print(f"Encrypted message: {encrypted_msg}")
print(f"Decrypted message: {decrypted_msg}")
