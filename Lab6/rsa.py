import random
from math import gcd
import hashlib
from sympy import isprime, mod_inverse

class RSA:
    def __init__(self, e: int, n: int = None, d: int = None):
        self.e = e
        self.n = n
        self.d = d

        # Only generate p, q, n, and d if both n and d are not already provided
        if self.n is None and self.d is None:
            self._generate_keys()

    def _generate_keys(self):
        # Generate two large distinct primes p and q
        self.p = self._generate_prime()
        self.q = self._generate_prime()
        while self.p == self.q:  # Ensure p != q
            self.q = self._generate_prime()

        # Calculate modulus n and totient φ(n)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)

        # Ensure e is coprime with φ(n)
        if gcd(self.e, self.phi_n) != 1:
            raise ValueError("Public exponent e must be coprime with φ(n).")

        # Calculate private key d as the modular inverse of e mod φ(n)
        self.d = mod_inverse(self.e, self.phi_n)

    def _generate_prime(self, start=10**50, end=10**51):
        # Generate a large prime number within the range
        while True:
            candidate = random.randint(start, end)
            if isprime(candidate):  # Use sympy's isprime for accuracy
                return candidate

    def encrypt(self, plaintext: int) -> int:
        # Encrypt the plaintext message (integer) using the public key
        if self.n is None:
            raise ValueError("Modulus (n) is required for encryption.")
        return pow(plaintext, self.e, self.n)

    def decrypt(self, ciphertext: int) -> int:
        # Decrypt the ciphertext message (integer) using the private key
        if self.d is None:
            raise ValueError("Private exponent (d) is required for decryption.")
        return pow(ciphertext, self.d, self.n)

    def sign(self, message: bytes) -> int:
        # Create a digital signature by hashing the message and encrypting the hash with the private key
        message_hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder="big")
        print(f"Debug: Signing hash {message_hash}")  # Debug log
        return self.decrypt(message_hash)  # Sign by decrypting the hash with the private key

    def verify(self, signature: int, message: bytes) -> bool:
        # Verify a digital signature by comparing the decrypted signature hash with the hash of the message
        message_hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder="big")
        decrypted_hash = self.encrypt(signature)  # Decrypt the signature with the public key
        print(f"Debug: Message hash {message_hash}")  # Debug log
        print(f"Debug: Decrypted signature hash {decrypted_hash}")  # Debug log
        return decrypted_hash == message_hash


if __name__ == "__main__":
    e = 65537  # Public exponent

    # Instantiate RSA
    cryptor = RSA(e)

    print(f"Generated primes p: {cryptor.p}, q: {cryptor.q}")
    print(f"Public key (e, n): ({cryptor.e}, {cryptor.n})")
    print(f"Private key (d, n): ({cryptor.d}, {cryptor.n})")

    # Test message
    message = b"Hello, this is a test message."

    # Sign the message
    signature = cryptor.sign(message)
    print(f"Signature: {signature}")

    # Verify the signature
    is_valid = cryptor.verify(signature, message)
    print(f"Signature valid: {is_valid}")

    # Encrypt and decrypt a plaintext message
    plaintext = 74934551197837615838790984411286222358639449529875366475640826113004513675453  # Example AES key
    ciphertext = cryptor.encrypt(plaintext)
    print(f"Encrypted message: {ciphertext}")

    decrypted = cryptor.decrypt(ciphertext)
    print(f"Decrypted message: {decrypted}")

    # Validate correctness
    assert plaintext == decrypted, "Decryption failed!"
