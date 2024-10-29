import socket
from cryptography.hazmat.primitives import hashes
from aes import AES
from key import Key
from rsa import RSA


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.client = None
        self.key_bytes = None
        self.aes_cryptor = None

        # Initialize RSA with standard public exponent
        self.rsa = RSA(65537)
        self.public_key = (self.rsa.e, self.rsa.n)

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(1)
        print(f"Server listening on {self.host}:{self.port}")
        self.client, addr = self.server.accept()
        print(f"Connected to client at {addr}")

    def send(self, message: str, hash_value: str):
        if not self.aes_cryptor:
            raise ValueError("AES cryptor not initialized. Perform key exchange first.")
        
        message_with_hash = f"{message}|{hash_value}"
        encrypted_message = self.aes_cryptor.encrypt(message_with_hash)
        self.client.sendall(encrypted_message)

    def receive(self, buffer_size=1024):
        if not self.aes_cryptor:
            raise ValueError("AES cryptor not initialized. Perform key exchange first.")

        encrypted_message = self.client.recv(buffer_size)
        decrypted_message = self.aes_cryptor.decrypt(encrypted_message)
        return decrypted_message

    def hash_message(self, message: str) -> str:
        if not self.key_bytes:
            raise ValueError("AES key not initialized. Perform key exchange first.")

        digest = hashes.Hash(hashes.SHA256())
        combined = message.encode('utf-8') + self.key_bytes
        digest.update(combined)
        return digest.finalize().hex()

    def exchange_keys(self):
        # Send public key to client
        public_key_str = f"{self.public_key[0]}|{self.public_key[1]}"
        self.client.sendall(public_key_str.encode('utf-8'))

        # Receive encrypted AES key from client
        encrypted_aes_key = int(self.client.recv(1024).decode('utf-8'))
        aes_key_as_int = self.rsa.decrypt(encrypted_aes_key)
        self.key_bytes = aes_key_as_int.to_bytes(32, byteorder='big')

        # Initialize AES cryptor
        self.aes_cryptor = AES(self.key_bytes)

    def close(self):
        if self.client:
            self.client.close()
        if self.server:
            self.server.close()


if __name__ == '__main__':
    HOST, PORT = '127.0.0.1', 6500

    server = Server(HOST, PORT)
    server.start()
    server.exchange_keys()
    print("Key exchange completed and AES cryptor initialized.")

    welcome_message = "Server has connected!"
    welcome_hash = server.hash_message(welcome_message)
    server.send(welcome_message, welcome_hash)
    print(f"Sent message: {welcome_message}")

    while True:
        try:
            received_data = server.receive()
            received_message, received_hash = received_data.split("|")

            recalculated_hash = server.hash_message(received_message)
            if recalculated_hash != received_hash:
                print("Warning: Message integrity was compromised.")
                break

            print(f"Received message: {received_message}, Hash: {received_hash}")

            if received_message.lower() == 'end chat':
                print("Chat ended by client.")
                break

            # Send a new message
            message_to_send = input("You: ")
            message_hash = server.hash_message(message_to_send)
            server.send(message_to_send, message_hash)

            if message_to_send.lower() == 'end chat':
                print("Chat ended by server.")
                break

        except ValueError:
            print("Error: Received data format is incorrect.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            break

    server.close()
