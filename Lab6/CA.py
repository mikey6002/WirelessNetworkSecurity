from rsa import RSA
import hashlib
import json


class CA:
    def __init__(self):
        # Generate CA's RSA key pair
        self.rsa = RSA(65537)
        self.public_key = (self.rsa.e, self.rsa.n)
        self.private_key = self.rsa.d

    def sign(self, server_public_key):
        """
        Sign the server's public key to create a certificate.

        :param server_public_key: The server's public key (e, n).
        :return: Certificate as a dictionary.
        """
        certificate_content = {
            "server_public_key": server_public_key,
            "issuer": "Trusted CA",
        }
        # Hash the certificate content
        certificate_hash = hashlib.sha256(json.dumps(certificate_content).encode()).hexdigest()

        # Sign the hash with CA's private key
        signature = self.rsa.sign(certificate_hash.encode())

        # Add signature to the certificate
        certificate_content["signature"] = signature
        return certificate_content

    @staticmethod
    def verify(certificate, recognized_ca_public_keys):
        print(f"Debug: Verifying certificate: {certificate}")  # Debug log
        print(f"Debug: Recognized CA keys: {recognized_ca_public_keys}")  # Debug log

        for ca_public_key in recognized_ca_public_keys:
            try:
                # Recreate the hash from the certificate content
                content_to_verify = {
                    "server_public_key": certificate["server_public_key"],
                    "issuer": certificate["issuer"],
                }
                certificate_hash = hashlib.sha256(json.dumps(content_to_verify).encode()).hexdigest()

                # Decrypt the signature using the CA's public key
                decrypted_hash = RSA(ca_public_key[0], ca_public_key[1]).encrypt(certificate["signature"])
                print(f"Debug: Certificate hash: {certificate_hash}, Decrypted hash: {decrypted_hash}")  # Debug log

                if certificate_hash == decrypted_hash:
                    print("Debug: Certificate is valid.")  # Debug log
                    return True
            except Exception as e:
                print(f"Debug: Verification error with CA key {ca_public_key}: {e}")  # Debug log

        print("Debug: Certificate is invalid or unrecognized.")  # Debug log
        return False
