
import socket
from cryptography.hazmat.primitives import hashes
from aes import AES  # AES encryption
from key import Key  # Key generation
from rsa import RSA  # RSA encryption for key exchange


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.key_bytes = None  # AES key in bytes

    def connect(self):
        # Establishes a connection to the server
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")

    def send(self, message: str, hash_value: str):
        # Encrypts and sends a message with its hash for integrity
        message_with_hash = message + "|" + hash_value
        cryptor = AES(self.key_bytes)  # AES instance with the established key
        encrypted_message = cryptor.encrypt(message_with_hash)
        self.client.sendall(encrypted_message)

    def receive(self, buffer_size=1024):
        # Receives and decrypts messages from the server
        encrypted_message = self.client.recv(buffer_size)
        cryptor = AES(self.key_bytes)  # AES instance with the established key
        decrypted_message = cryptor.decrypt(encrypted_message)
        return decrypted_message

    def hash_message(self, message: str, key: bytes) -> str:
        # Generates SHA-256 hash for the message and key combined
        digest = hashes.Hash(hashes.SHA256())
        combined = message.encode('ascii') + key
        digest.update(combined)
        return digest.finalize().hex()

    def exchange_keys(self):
        # Handles key exchange using RSA encryption
        # Receive server's RSA public key
        print("Receiving server's public RSA key...")
        public_key = self.client.recv(1024).decode('utf-8')
        e, n = [int(x) for x in public_key.split('|')]
        rsa = RSA(e, n)  # RSA instance for encryption with server's public key
        print(f"Received public key: (e={e}, n={n})")

        # Generate a new AES key for communication
        key = Key()
        self.aes_key = key.gen(256)
        print(f"Generated AES key (bytes): {self.aes_key}")

        # Encrypt AES key with RSA and send it to the server
        aes_key_as_int = int.from_bytes(self.aes_key, byteorder='big')
        encrypted_aes_key = rsa.encrypt(aes_key_as_int)
        print(f"Encrypted AES key to send: {encrypted_aes_key}")
        self.client.sendall(str(encrypted_aes_key).encode('utf-8'))
        self.key_bytes = self.aes_key  # Store AES key for session encryption
        return self.key_bytes

    def close(self):
        # Closes the client socket
        self.client.close()


if __name__ == '__main__':
    HOST, PORT = '127.0.0.1', 6500  # Default server address

    client = Client(HOST, PORT)
    client.connect()
    key_bytes = client.exchange_keys()

    if key_bytes is None:
        print("Error: Key exchange failed.")
        client.close()
        exit(1)

    # Initial message
    intro_message = "Client has connected!"
    intro_hash = client.hash_message(intro_message, key_bytes)
    client.send(intro_message, intro_hash)
    print(f"Sent message: {intro_message}")

    while True:
        # Receive and process server message
        received_data = client.receive()
        try:
            received_message, received_hash = received_data.split("|")
        except ValueError:
            print("Error: Received data format is incorrect.")
            break
        
        # Verify message integrity
        recalculated_hash = client.hash_message(received_message, key_bytes)
        if recalculated_hash != received_hash:
            print("Warning: Message integrity compromised.")
            break
        else:
            print(f"Received message: {received_message} (Hash: {received_hash})")

        # Check if the server ended the chat
        if received_message.lower() == 'end chat':
            print("Chat ended by server.")
            break

        # Send new message to server
        message_to_send = input("You: ")
        message_hash = client.hash_message(message_to_send, key_bytes)
        client.send(message_to_send, message_hash)

        if message_to_send.lower() == 'end chat':
            print("Chat ended by client.")
            break

    client.close()

