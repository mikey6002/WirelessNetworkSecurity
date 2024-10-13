import random
import math 

# Predefined small prime numbers
small_primes = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 
    37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113, 127
]

def is_prime(n):
    """Check if a number is prime."""
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime():
    """Select a random prime from the list of small primes."""
    return random.choice(small_primes)

def mod_inverse(a, m):
    """Compute the modular inverse of a with respect to m."""
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

def generate_keypair():
    """Generate a pair of RSA keys using small primes."""
    p = generate_prime()
    q = generate_prime()
    while p == q:  # Ensure p and q are distinct
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 5  # Choose a small prime for e
    while math.gcd(e, phi) != 1:
        e += 2  # Increment e to find a valid one
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def mod_pow(base, exponent, modulus):
    """Perform modular exponentiation."""
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def encrypt(public_key, plaintext):
    """Encrypt a message using the public key."""
    e, n = public_key
    return [mod_pow(ord(char), e, n) for char in plaintext]

def decrypt(private_key, ciphertext):
    """Decrypt a message using the private key."""
    d, n = private_key
    return ''.join([chr(mod_pow(char, d, n)) for char in ciphertext])

# Example usage
if __name__ == "__main__":
    public_key, private_key = generate_keypair()
    message = "Hello, RSA!"
    encrypted_msg = encrypt(public_key, message)
    decrypted_msg = decrypt(private_key, encrypted_msg)

    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted_msg}")
    print(f"Decrypted message: {decrypted_msg}")
