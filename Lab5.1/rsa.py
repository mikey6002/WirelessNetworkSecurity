import random
from math import gcd
import hashlib

def is_prime(n, k=5):
   #prime check
    if n % 2 == 0:
        return False

    # Write (n - 1) as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    # Perform k tests
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
    #refactored to generate large primes
    while True:
        num = random.randint(start, end)
        if is_prime(num):
            return num

class RSA:

    def __init__(self, e: int, n: int = None, d: int = None):
        self.e = e
        self.n = n
        self.d = d

        # Only generate p, q, n, and d if both n and d are not already generated
        if self.n is None and self.d is None:
            self._generate_keys()

    def _generate_keys(self):
        # Generate two large prime numbers p and q
        self.p = generate_prime()
        self.q = generate_prime()
        
        while self.p == self.q:
            self.q = generate_prime()

        # Calculate n and phi(n)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)

        # Calculate d, the modular inverse of e mod phi(n)
        self.d = self._mod_inverse(self.e, self.phi_n)

    def _mod_inverse(self, e, phi_n):
        #find d such that (d * e) % phi_n = 1 using extended Euclidean algo.
        d, x1, x2, y1 = 0, 0, 1, 1
        temp_phi = phi_n

        while e > 0:
            temp1 = temp_phi // e
            temp2 = temp_phi - temp1 * e
            temp_phi, e = e, temp2

            x = x2 - temp1 * x1
            y = d - temp1 * y1

            x2, x1 = x1, x
            d, y1 = y1, y

        if temp_phi == 1:
            return d + phi_n

    def encrypt(self, plaintext: int) -> int:
        #Encrypt the plaintext message (integer) using the public key.
        if self.n is None:
            raise ValueError("Private exponent (n) is required for decryption")
        return pow(plaintext, self.e, self.n)

    #applies private key to the hash signature to get the original message
    def decrypt(self, ciphertext: int) -> int:
        #Decrypt the ciphertext message (integer) using the private key.
        if self.d is None:
            raise ValueError("Private exponent (d) is required for decryption")
        return pow(ciphertext, self.d, self.n) #sign = hash^d mod n

    def sign(self, message: bytes) -> int:
        #Createing a digital signature by hashing and encrypting the hash with the private key
        # Hash the message using SHA-256
        message_hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
        # Sign by decrypting the hash with the private key (d, n)
        return self.decrypt(message_hash)

     #Verify a digital signature by decrypting it and comparing with the message hash
    def verify(self, signature: int, message: bytes) -> bool:
        # Hash the message
        message_hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
        # Decrypt the signature with the public key (encrypt function) to retrieve the hash
        decrypted_hash = self.encrypt(signature)
        # Check if the decrypted hash matches the message hash
        return decrypted_hash == message_hash


if __name__ == '__main__':
    e = 65537  # public exponent

    # Instantiate RSA
    cryptor = RSA(e)

    print(f"Generated primes p: {cryptor.p}, q: {cryptor.q}")
    print(f"Public key (e, n): ({cryptor.e}, {cryptor.n})")
    print(f"Private key (d, n): ({cryptor.d}, {cryptor.n})")

    plaintext = 74934551197837615838790984411286222358639449529875366475640826113004513675453  # Message to encrypt (AES key length)
    message = b"Hello, this is a test message."

    # Sign the message
    signature = cryptor.sign(message)
    print(f"Signature: {signature}")

    # Verify the signature
    result = cryptor.verify(signature, message)
    print(f"Signature valid: {result}")

    
    print(f"Original message: {plaintext}")

    # Encrypt
    ciphertext = cryptor.encrypt(plaintext)
    print(f"Encrypted message: {ciphertext}")

    # Decrypt
    decrypted = cryptor.decrypt(ciphertext)
    print(f"Decrypted message: {decrypted}")

    # Validate
    assert plaintext == decrypted, "Incorrect decryption!"