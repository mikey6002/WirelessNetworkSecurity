from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class RSAEncryptor:
    """
    A simple RSA wrapper for encryption and decryption.
    Padding is handled by OAEP.
    """
    
    def __init__(self, private_key=None, public_key=None):
        if private_key is None and public_key is None:
            # Generate new RSA key pair if not provided
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = private_key
            self.public_key = public_key

    def encrypt(self, plaintext: str) -> bytes:
        plaintext_bytes = bytes(plaintext, 'ascii')
        ciphertext = self.public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        # Decrypt the ciphertext using the private key
        decrypted = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted  # Return as bytes instead of decoding to a string

    def serialize_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


if __name__ == '__main__':
    # Instantiate RSA encryptor (generates a key pair)
    rsa_cryptor = RSAEncryptor()

    # Your custom plaintext message
    plaintext = "Good morning!"
    
    # Encrypt the plaintext
    ciphertext = rsa_cryptor.encrypt(plaintext)

    # Decrypt the ciphertext
    decrypted = rsa_cryptor.decrypt(ciphertext)

    # Convert the decrypted bytes back to a string
    decrypted_str = decrypted.decode('ascii')

    # Check if everything works
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted_str}")
    assert plaintext == decrypted_str, "Incorrect decryption!"

    # Serialize keys if needed
    private_key_pem = rsa_cryptor.serialize_private_key()
    public_key_pem = rsa_cryptor.serialize_public_key()

    print(f"Private Key:\n{private_key_pem.decode()}")
    print(f"Public Key:\n{public_key_pem.decode()}")
