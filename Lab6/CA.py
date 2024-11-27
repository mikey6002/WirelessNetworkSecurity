import hashlib

class CA:
    def __init__(self, rsa_instance):
        self.rsa = rsa_instance
        self.public_key = (self.rsa.e, self.rsa.n)
        self.private_key = self.rsa.d

    def sign(self, server_public_key):
        # Create a consistent string format for the certificate
        issuer = "Trusted CA"
        content_to_sign = f"{server_public_key[0]}|{server_public_key[1]}|{issuer}"
        
        # Hash the content and convert to an integer
        certificate_hash = hashlib.sha256(content_to_sign.encode()).hexdigest()
        int_certificate_hash = int(certificate_hash, 16)  # Convert hex to int
        print(f"Debug: Certificate hash to sign (int): {int_certificate_hash}")  # Debug log
        
        # Sign the hash using the private key
        signature = self.rsa.decrypt(int_certificate_hash)  # Signing with private key
        print(f"Debug: Signature: {signature}")  # Debug log
        
        # Return the certificate
        return {
            "server_public_key": server_public_key,
            "issuer": issuer,
            "signature": signature,
        }

    @staticmethod
    def verify(certificate, recognized_ca_public_keys):
        for ca_public_key in recognized_ca_public_keys:
            try:
                # Reconstruct the consistent format for verification
                content_to_verify = f"{certificate['server_public_key'][0]}|{certificate['server_public_key'][1]}|{certificate['issuer']}"
                
                # Hash the content and convert to an integer
                calculated_hash = hashlib.sha256(content_to_verify.encode()).hexdigest()
                int_calculated_hash = int(calculated_hash, 16)  # Convert hex to int
                
                # Decrypt the signature with the public key
                rsa_instance = RSA(ca_public_key[0], ca_public_key[1])
                decrypted_hash = rsa_instance.encrypt(certificate["signature"])
                print(f"Debug: Calculated certificate hash (int): {int_calculated_hash}")  # Debug log
                print(f"Debug: Decrypted certificate hash (int): {decrypted_hash}")  # Debug log
                
                # Compare the decrypted hash with the calculated hash
                if int_calculated_hash == decrypted_hash:
                    return True
            except Exception as e:
                print(f"Debug: Verification error with CA key {ca_public_key}: {e}")
        return False
