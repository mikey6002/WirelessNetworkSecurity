import socket
import json
from cryptography.hazmat.primitives import hashes
from rsa import RSA
from Ca import CA


class Client:
    def __init__(self, host, port, recognized_cas):
        self.host = host
        self.port = port
        self.client = None

        self.rsa = RSA(65537)
        self.public_key = (self.rsa.e, self.rsa.n)
        self.private_key = self.rsa.d
        self.server_public_key = None
        self.recognized_cas = recognized_cas  # List of recognized CA public keys

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

    def validate_certificate(self, certificate):
        """
        Validate the server's certificate.
        """
        return CA.verify(certificate, self.recognized_cas)

    def exchange_keys(self):
        """
        Validate the server's certificate, and exchange public keys.
        """
        # Receive the server's certificate
        certificate_data = self.client.recv(2048).decode('utf-8')
        certificate = json.loads(certificate_data)

        # Validate the server's certificate
        if not self.validate_certificate(certificate):
            raise ValueError("Server certificate is invalid or untrusted.")

        print("Server certificate validated successfully.")
        self.server_public_key = certificate["server_public_key"]

        # Send the client's public key to the server
        self.client.sendall(f"{self.public_key[0]}|{self.public_key[1]}".encode('utf-8'))
        print("Sent client's public key to server.")

    def send(self, message: str):
        """
        Sign the message with the client's private key and send.
        """
        message_bytes = message.encode('utf-8')
        signature = self.rsa.sign(message_bytes)
        data = f"{message}|{signature}"
        self.client.sendall(data.encode('utf-8'))
        print("Sent signed message to server.")

    def receive(self, buffer_size=1024):
        """
        Receive a message and verify its signature.
        """
        data = self.client.recv(2048).decode('utf-8')
        message, signature = data.split("|")
        message = message.encode('utf-8')
        signature = int(signature)

        # Verify the signature using the server's public key
        is_valid = self.server_public_key.verify(signature, message)
        if is_valid:
            print("Signature verified successfully.")
            return message.decode('utf-8')
        else:
            print("Signature verification failed.")
            return None

    def close(self):
        self.client.close()


if __name__ == '__main__':
    HOST, PORT = '10.109.21.177', 9999

    # Simulate a trusted CA and server certificate generation
    ca = CA()
    recognized_cas = [ca.public_key]

    # Simulate server's RSA keys
    server_rsa = RSA()
    server_public_key = server_rsa.generate_key_pair()[1]

    # CA signs the server's public key
    server_certificate = ca.sign(server_public_key)

    # Client connects to server
    client = Client(HOST, PORT, recognized_cas)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")

    # Validate certificate and exchange keys
    try:
        client.exchange_keys()
        print("Key exchange successful.")

        intro = "Client has connected!"
        client.send(intro)
        print(f"Sent message: {intro}")

        while True:
            received_message = client.receive()
            if received_message is None:
                print("Message verification failed or message is empty.")
                break
            print(f"Client: {received_message}")

            if received_message.lower() == 'end chat':
                print("Chat ended by server.")
                break

            # Read for message
            message_to_send = input("You: ")
            client.send(message_to_send)

            # Terminate if sent message is "end chat"
            if message_to_send.lower() == 'end chat':
                print("Chat ended by client.")
                break

    except Exception as e:
        print(f"Error during key exchange or communication: {e}")

    client.close()
