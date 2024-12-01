from rsa import RSA

class CA:
    def __init__(self):
        # Generate the CA's RSA key pair
        self.rsa = RSA(65537)
        self.public_key = (self.rsa.e, self.rsa.n)  # Public key (e, n)
        self.private_key = self.rsa.d  # Private key (d)

        # Export the public key to a file
        self.export_public_key()

    def export_public_key(self):
        # Export the CA's public key to a file for use by client.
        ca_public_key = f"{self.public_key[0]}|{self.public_key[1]}"
        with open("ca_public_key.txt", "w") as file:
            file.write(ca_public_key)
        print("CA's public key has been exported to 'ca_public_key.txt'.")

    def sign(self, server_public_key: tuple) -> tuple:
        #Sign the server's public key to generate a certificate.
        key_string = f"{server_public_key[0]}|{server_public_key[1]}"
        key_bytes = key_string.encode('utf-8')
        signature = self.rsa.sign(key_bytes)
    
        # Ensure the signature is returned as an integer
        print(f"Signing certificate: {key_string} with signature: {signature}")
        #return A certificate containing the signed server public key
        return key_string, signature


    def verify(self, certificate: tuple, ca_public_key: tuple) -> bool:
        #Verify a certificate using the CA's public key.
        key_string, signature = certificate
        key_bytes = key_string.encode('utf-8')

        # Create an RSA instance for the CA's public key
        ca_rsa = RSA(e=ca_public_key[0], n=ca_public_key[1])

        # Verify the signature by decrypting it with the CA's public key
        return ca_rsa.verify(signature, key_bytes)

if __name__ == "__main__":
    # Test the CA functionality
    ca = CA()
    print(f"CA's public key: {ca.public_key}")
