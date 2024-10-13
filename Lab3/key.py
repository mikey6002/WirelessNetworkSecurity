import random
from math import isqrt
from typing import Tuple

class Key:
    """
    A class for generating, reading, and writing RSA keys.
    """

    def __init__(self):
        self.default_key_size = 2048
        self.default_public_exponent = 65537

    def is_prime(self, num: int) -> bool:
        """Check if a number is prime using the Miller-Rabin primality test."""
        if num <= 1 or num == 4:
            return False
        if num <= 3:
            return True
        
        d = num - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        
        def try_composite(a):
            if pow(a, d, num) == 1:
                return False
            for i in range(s):
                if pow(a, 2**i * d, num) == num - 1:
                    return False
            return True
        
        for _ in range(5):  # number of tests
            a = random.randrange(2, num - 1)
            if try_composite(a):
                return False
        return True

    def gen_prime(self, bits: int) -> int:
        """Generates a large prime number of the specified bit length."""
        while True:
            prime_candidate = random.getrandbits(bits)
            prime_candidate |= (1 << (bits - 1)) | 1
            if self.is_prime(prime_candidate):
                return prime_candidate

    def gen_rsa_keypair(self, key_size: int = None) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """Generates an RSA key pair."""
        if key_size is None:
            key_size = self.default_key_size

        p = self.gen_prime(key_size // 2)
        q = self.gen_prime(key_size // 2)
        n = p * q
        phi_n = (p - 1) * (q - 1)

        e = self.default_public_exponent
        if phi_n % e == 0:
            raise ValueError("Public exponent e is not coprime to φ(n). Please try again.")

        d = self.mod_inverse(e, phi_n)

        public_key = (e, n)
        private_key = (d, n)
        return public_key, private_key

    def mod_inverse(self, a: int, m: int) -> int:
        """Compute the modular inverse of a under modulo m using the extended Euclidean algorithm."""
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            else:
                g, y, x = egcd(b % a, a)
                return g, x - (b // a) * y, y

        g, x, _ = egcd(a, m)
        if g != 1:
            raise ValueError("Modular inverse does not exist")
        else:
            return x % m

    def read(self, key_file: str) -> Tuple[int, int]:
        with open(key_file, 'r') as f:
            key = eval(f.read())
        return key

    def write(self, key: Tuple[int, int], key_file: str) -> None:
        with open(key_file, 'w') as f:
            f.write(str(key))

if __name__ == '__main__':
    key = Key()
    key_size = 2048  # Increased key size for better security

    # Generate an RSA key pair
    public_key, private_key = key.gen_rsa_keypair(key_size)
    print("Generated RSA Key Pair:")
    print("Public Key (e, n):", public_key)
    print("Private Key (d, n):", private_key)

    # Write the keys to files
    public_key_file = 'public_key.txt'
    private_key_file = 'private_key.txt'
    key.write(public_key, public_key_file)
    key.write(private_key, private_key_file)
    print("Keys written to files:", public_key_file, private_key_file)

    # Read the keys from files
    read_public_key = key.read(public_key_file)
    read_private_key = key.read(private_key_file)
    print("Read Public Key from file:", public_key_file)
    print("Public Key:", read_public_key)
    print("Read Private Key from file:", private_key_file)
    print("Private Key:", read_private_key)