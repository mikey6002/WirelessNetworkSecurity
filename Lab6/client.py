import socket
from rsa import RSA
from CA import CA
from hashlib import sha256


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
        print(f"Debug: Connected to server at {self.host}:{self.port}")  # Debug log

    def validate_certificate(self, certificate):
        if "signature" not in certificate or "server_public_key" not in certificate:
            print("Debug: Invalid certificate format.")  # Debug log
            return False
        print(f"Debug: Validating certificate: {certificate}")  # Debug log
        result = CA.verify(certificate, self.recognized_cas)
        print(f"Debug: Certificate validation result: {result}")  # Debug log
        return result
        
    def exchange_keys(self):
        try:
            # Receive the server's certificate
            certificate_data = self.client.recv(1024).decode('utf-8')
            print(f"Debug: Received certificate data: {certificate_data}")  # Debug log

            # Parse the certificate
            parts = certificate_data.split('|')
            if len(parts) != 4:
                raise ValueError("Certificate format mismatch")
            certificate = {
                'server_public_key': (int(parts[0]), int(parts[1])),
                'issuer': parts[2],
                'signature': int(parts[3])
            }
            print(f"Debug: Parsed certificate: {certificate}")  # Debug log

            # Validate the certificate
            if not self.validate_certificate(certificate):
                print("Debug: Certificate verification failed. Closing connection.")  # Debug log
                self.client.close()
                raise ValueError("Server certificate is invalid or untrusted.")

            print("Debug: Server certificate validated successfully.")  # Debug log
            self.server_public_key = RSA(certificate["server_public_key"][0], certificate["server_public_key"][1])

            # Send the client's public key
            self.client.sendall(f"{self.public_key[0]}|{self.public_key[1]}".encode('utf-8'))
            print(f"Debug: Sent client public key: {self.public_key}")  # Debug log

        except Exception as e:
            print(f"Debug: Error during key exchange: {e}")  # Debug log
            self.close()
            raise

    def send(self, message: str):
        message_bytes = message.encode('utf-8')
        signature = self.rsa.sign(message_bytes)
        data = f"{message}|{signature}"
        try:
            self.client.sendall(data.encode('utf-8'))
            print(f"Debug: Sent signed message: {message}")  # Debug log
        except socket.error as e:
            print(f"Debug: Socket error while sending: {e}")  # Debug log
            self.close()
            raise

    def receive(self, buffer_size=1024):
        try:
            data = self.client.recv(2048).decode('utf-8')
            if not data.strip():
                print("Debug: Received empty data.")  # Debug log
                return None

            message, signature = data.split("|")
            message = message.encode('utf-8')
            signature = int(signature)

            is_valid = self.server_public_key.verify(signature, message)
            print(f"Debug: Signature verification result: {is_valid}")  # Debug log
            if is_valid:
                return message.decode('utf-8')
            else:
                print("Debug: Signature verification failed.")  # Debug log
                return None
        except Exception as e:
            print(f"Debug: Error during message processing: {e}")  # Debug log
            return None

    def close(self):
        if self.client:
            print("Debug: Closing client connection.")  # Debug log
            self.client.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.1.17', 6500

    e = 65537
    # Initialize the CA
    rsa_instance = RSA(e)
    ca = CA(rsa_instance)
    recognized_cas = [ca.public_key]

    client = Client(HOST, PORT, recognized_cas)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")

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

            message_to_send = input("You: ")
            client.send(message_to_send)

            if message_to_send.lower() == 'end chat':
                print("Chat ended by client.")
                break

    except Exception as e:
        print(f"Debug: Error during key exchange or communication: {e}")  # Debug log

    client.close()
