import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class RSA:
    """
    A simple RSA wrapper for encryption and decryption.
    """

    def __init__(self, key_size: int):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, plaintext: str) -> bytes:
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = self.public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        decrypted_bytes = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_bytes.decode('utf-8')


if __name__ == '__main__':
    # Specify the key size for RSA
    key_size = 2048  # Common size for RSA keys
    
    # Instantiate an RSA cryptor
    rsa_cryptor = RSA(key_size)

    # Your custom plaintext message
    plaintext = "Good morning!"
    
    # Encrypt
    ciphertext = rsa_cryptor.encrypt(plaintext)
    
    # Decrypt
    decrypted = rsa_cryptor.decrypt(ciphertext)

    # Check if everything works
    print(f"plaintext: {plaintext}")
    # Typically unreadable, but we can print it as hex
    print(f"ciphertext: {ciphertext.hex()}")
    # Check decrypted message
    print(f"decrypted: {decrypted}")
    # Report if there is something wrong
    assert plaintext == decrypted, "Incorrect decryption!"

