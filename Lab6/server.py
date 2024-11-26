import socket
import json
from cryptography.hazmat.primitives import hashes
from rsa import RSA
from Ca import CA


class Server:
    def __init__(self, host, port, ca):
        self.host = host
        self.port = port
        self.server = None
        self.client = None

        self.rsa = RSA(65537)  # Using standard public exponent
        self.public_key = (self.rsa.e, self.rsa.n)  # Public key
        self.private_key = (self.rsa.d, self.rsa.n)  # Private key
        self.aes_key = None
        self.client_public_key = None

        self.ca = ca  # The CA instance for signing
        self.certificate = self.ca.sign(self.public_key)  # Signed certificate

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)

    def accept(self):
        self.client, addr = self.server.accept()
        return addr

    def exchange_keys(self):
        # Send the server's signed certificate to the client
        self.client.sendall(json.dumps(self.certificate).encode('utf-8'))
        print("Sent server's signed certificate to client.")

        # Receive the client's public key
        client_key_data = self.client.recv(1024).decode('utf-8')
        e, n = map(int, client_key_data.split('|'))  # Convert both e and n to int
        self.client_public_key = RSA(e, n)  # Initialize client's public key
        print("Received client's public key.")

    def receive(self, buffer_size=1024):
        # Receive a message and its signature
        data = self.client.recv(2048).decode('utf-8')  # Bytes to string
        message, signature = data.split("|")  # Split received data into message and signature
        message = message.encode('utf-8')  # Encode message into bytes (signature requires original message)
        signature = int(signature)  # Convert signature to int

        # Verify the signature using the client's public key
        is_valid = self.client_public_key.verify(signature, message)
        if is_valid:
            print("Signature verified successfully.")
            return message.decode('utf-8')
        else:
            print("Signature verification failed.")
            return None

    def send(self, message: str):
        message_bytes = message.encode('utf-8')
        signature = self.rsa.sign(message_bytes)  # Sign the message with the server's private key
        data = f"{message}|{signature}"
        self.client.sendall(data.encode('utf-8'))  # Send signed message to client
        print("Sent signed message to client.")

    def close(self):
        self.client.close()
        self.server.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.2.37', 9999

    # Initialize the CA
    ca = CA()

    # Initialize the server with the CA
    server = Server(HOST, PORT, ca)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    try:
        server.exchange_keys()

        while True:
            # Wait for a message
            received_message = server.receive()
            if received_message is None:
                print("Message verification failed or message is empty.")
                break
            print(f"Client: {received_message}")

            if received_message.lower() == 'end chat':
                print("Chat ended by client.")
                break

            # Read for message
            message_to_send = input("You: ")
            server.send(message_to_send)

            # Terminate if sent message is "end chat"
            if message_to_send.lower() == 'end chat':
                print("Chat ended by server.")
                break

    except Exception as e:
        print(f"Error during communication: {e}")

    server.close()
