from rsa import RSA
import hashlib
import json

class CA:
    def __init__(self):
        # Generate CA's RSA key pair
        self.rsa = RSA()
        self.private_key, self.public_key = self.rsa.generate_key_pair()
    
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
        signature = self.rsa.encrypt(certificate_hash, self.private_key)
        
        # Add signature to the certificate
        certificate_content["signature"] = signature
        return certificate_content
    
    @staticmethod
    def verify(certificate, recognized_ca_public_keys):
        """
        Verify a certificate using a recognized CA's public key.
        
        :param certificate: Certificate as a dictionary.
        :param recognized_ca_public_keys: List of recognized CA public keys.
        :return: True if valid, False otherwise.
        """
        # Extract the CA public key from recognized list
        for ca_public_key in recognized_ca_public_keys:
            try:
                # Recreate the hash from the certificate content
                content_to_verify = {
                    "server_public_key": certificate["server_public_key"],
                    "issuer": certificate["issuer"],
                }
                certificate_hash = hashlib.sha256(json.dumps(content_to_verify).encode()).hexdigest()
                
                # Decrypt the signature using the CA's public key
                decrypted_hash = RSA().decrypt(certificate["signature"], ca_public_key)
                
                # Verify the integrity of the certificate
                if certificate_hash == decrypted_hash:
                    return True
            except Exception as e:
                continue
        
        return False
