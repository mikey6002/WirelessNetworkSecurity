import socket
from cryptography.hazmat.primitives import hashes
from aes import AES  # AES encryption
from key import Key  # Key generation
from rsa import RSA  # RSA encryption for key exchange


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.client = None
        self.key_bytes = None  # AES key in bytes

        # RSA key pair for encryption/decryption
        self.rsa = RSA(65537)  # Public exponent
        self.public_key = (self.rsa.public_expo, self.rsa.n)  # Public key
        self.private_key = (self.rsa.d, self.rsa.n)  # Private key
        self.aes_key = None  # Session AES key

    def start(self):
        # Initializes the server socket and listens for connections
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Server started and listening on {self.host}:{self.port}")

    def accept(self):
        # Accepts an incoming client connection
        self.client, addr = self.server.accept()
        print(f"Accepted connection from {addr}")
        return addr

    def receive(self, buffer_size=1024):
        # Receives an encrypted message from the client
        encrypted_message = self.client.recv(buffer_size)
        cryptor = AES(self.key_bytes)  # AES instance with the established key
        decrypted_message = cryptor.decrypt(encrypted_message)
        return decrypted_message

    def send(self, message: str, hash_value: str):
        # Encrypts and sends a message with its hash for integrity
        message_with_hash = message + "|" + hash_value
        cryptor = AES(self.key_bytes)  # AES instance with the established key
        encrypted_message = cryptor.encrypt(message_with_hash)
        self.client.sendall(encrypted_message)

    def exchange_keys(self):
        # Handles key exchange with the client using RSA encryption
        # Send server's RSA public key to client
        public_key_str = f"{self.public_key[0]}|{self.public_key[1]}"
        self.client.sendall(public_key_str.encode('utf-8'))

        # Receive encrypted AES key from client
        encrypted_aes_key = int(self.client.recv(1024).decode('utf-8'))
        aes_key_as_int = self.rsa.decrypt(encrypted_aes_key)
        self.key_bytes = aes_key_as_int.to_bytes((aes_key_as_int.bit_length() + 7) // 8, byteorder='big')
        print(f"Established AES session key: {self.key_bytes}")

    def hash_message(self, message: str, key: bytes) -> str:
        # Generates SHA-256 hash for the message and key combined
        digest = hashes.Hash(hashes.SHA256())
        combined = message.encode('ascii') + key
        digest.update(combined)
        return digest.finalize().hex()


    def close(self):
        # Closes client and server sockets
        if self.client:
            self.client.close()
        if self.server:
            self.server.close()


if __name__ == '__main__':
    HOST, PORT = '127.0.0.1', 6500  # Default server address

    server = Server(HOST, PORT)
    server.start()

    try:
        addr = server.accept()
        server.exchange_keys()

        while True:
            # Receive and process client message
            received_data = server.receive()
            try:
                received_message, received_hash = received_data.split("|")
            except ValueError:
                print("Error: Received data format is incorrect.")
                break

            # Verify message integrity
            recalculated_hash = server.hash_message(received_message, server.key_bytes)
            if recalculated_hash != received_hash:
                print("Warning: Message integrity compromised.")
                break
            else:
                print(f"Received message: {received_message} (Hash: {received_hash})")

            # Check if the client ended the chat
            if received_message.lower() == 'end chat':
                print("Chat ended by client.")
                break

            # Send new message to client
            message_to_send = input("You: ")
            message_hash = server.hash_message(message_to_send, server.key_bytes)
            server.send(message_to_send, message_hash)

            if message_to_send.lower() == 'end chat':
                print("Chat ended by server.")
                break

    finally:
        server.close()