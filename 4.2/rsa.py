import random
from math import gcd

def is_prime(n, k=5):
    """Efficient Miller-Rabin primality test."""
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Express n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    # Perform k rounds of testing with different random bases
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(start=10**50, end=10**51):
    """Generate a large prime number within a specified range."""
    while True:
        # Use a random odd number as a prime candidate
        candidate = random.randrange(start | 1, end, 2)
        if is_prime(candidate):
            return candidate

class RSA:
    def __init__(self, e: int, n: int = None, d: int = None):
        """Initialize RSA object with a public exponent e, and optionally n and d."""
        self.e = e
        self.n = n
        self.d = d

        # Generate p, q, n, and d if not already provided
        if self.n is None and self.d is None:
            self._generate_keys()

    def _generate_keys(self):
        """Generate RSA key components p, q, n, and d."""
        # Efficiently generate two large, distinct prime numbers
        self.p = generate_prime()
        self.q = generate_prime()
        
        while self.p == self.q:
            self.q = generate_prime()

        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.d = self._mod_inverse(self.e, self.phi_n)

    def _mod_inverse(self, e, phi_n):
        """Compute modular inverse of e mod phi_n using Extended Euclidean Algorithm."""
        t, new_t = 0, 1
        r, new_r = phi_n, e

        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t - quotient * new_t
            r, new_r = new_r, r - quotient * new_r

        if r > 1:
            raise ValueError("e and phi_n are not coprime")
        if t < 0:
            t = t + phi_n
        return t

    def encrypt(self, plaintext: int) -> int:
        """Encrypt plaintext integer using the public key."""
        if self.n is None:
            raise ValueError("Public modulus (n) is required for encryption.")
        return pow(plaintext, self.e, self.n)

    def decrypt(self, ciphertext: int) -> int:
        """Decrypt ciphertext integer using the private key."""
        if self.d is None:
            raise ValueError("Private exponent (d) is required for decryption.")
        return pow(ciphertext, self.d, self.n)


if __name__ == '__main__':
    e = 65537  # Common public exponent

    # Initialize RSA and generate keys
    rsa_instance = RSA(e)

    print(f"Generated primes p: {rsa_instance.p}, q: {rsa_instance.q}")
    print(f"Public key (e, n): ({rsa_instance.e}, {rsa_instance.n})")
    print(f"Private key (d, n): ({rsa_instance.d}, {rsa_instance.n})")

    plaintext = 74934551197837615838790984411286222358639449529875366475640826113004513675453
    print(f"Original message: {plaintext}")

    # Encrypt the message
    ciphertext = rsa_instance.encrypt(plaintext)
    print(f"Encrypted message: {ciphertext}")

    # Decrypt the message
    decrypted_message = rsa_instance.decrypt(ciphertext)
    print(f"Decrypted message: {decrypted_message}")

    # Verify decryption
    assert plaintext == decrypted_message, "Decryption failed!"
