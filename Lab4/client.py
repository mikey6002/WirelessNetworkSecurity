import socket
from cryptography.hazmat.primitives import serialization
from rsa import RSAEncryptor
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.asymmetric import padding
from aes import AES  
import random


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = None
        self.server_public_key = None  # Will hold the server's public key
        self.aes_key = None  # This will hold the AES key for message encryption

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

        # Receive server's public key upon connection
        public_key_pem = self.client.recv(1024)  # Adjust buffer size as needed
        self.server_public_key = serialization.load_pem_public_key(public_key_pem)

    def send_aes_key(self):
        # Encrypt the AES key using the server's RSA public key
        encrypted_aes_key = self.server_public_key.encrypt(
            self.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Send the encrypted AES key to the server
        self.client.sendall(encrypted_aes_key)

    def send(self, message: str):
        if not self.aes_key:
            raise ValueError("AES key has not been set. Cannot send message.")

        # Encrypt the message using AES
        aes_cryptor = AES(self.aes_key) 
        encrypted_message = aes_cryptor.encrypt(message)
        self.client.sendall(encrypted_message)

    def receive(self, buffer_size=1024):
        encrypted_message = self.client.recv(buffer_size)
        aes_cryptor = AES(self.aes_key)  # Use the AES key for decryption
        decrypted_message = aes_cryptor.decrypt(encrypted_message)
        return decrypted_message

    def hash_message(self, message: str) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message.encode('ascii'))
        return digest.finalize().hex()

    def close(self):
        self.client.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.1.7', 65000  # Change this if the server is on a different host

    client = Client(HOST, PORT)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")

    # Generate a random AES key (256 bits)
    key_len = 256
    client.aes_key = bytes([random.randint(0, 255) for _ in range(key_len // 8)])

    # Send the AES key to the server
    client.send_aes_key()

    while True:
        # Send message
        message_to_send = input("You: ")
        client.send(message_to_send)

        if message_to_send.lower() == 'end chat':
            print("Chat ended by client.")
            break

        # Receive message
        received_data = client.receive()
        print(f"Message received: {received_data}")
        if received_data == 'end chat':
            print("Chat ended by server.")
            break

    client.close()