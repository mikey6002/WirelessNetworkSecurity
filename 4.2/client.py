import socket
from cryptography.hazmat.primitives import hashes
from aes import AES
from key import Key
from rsa import RSA


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.key_bytes = None
        self.client = None
        self.aes_cryptor = None

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

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
        # Receive the server's public key
        public_key = self.client.recv(1024).decode('utf-8')
        e, n = [int(x) for x in public_key.split('|')]
        rsa = RSA(e, n)

        # Generate AES key and store it
        key_gen = Key()
        self.key_bytes = key_gen.gen(256)

        # Encrypt AES key with the server's public key
        aes_key_as_int = int.from_bytes(self.key_bytes, byteorder='big')
        encrypted_aes_key = rsa.encrypt(aes_key_as_int)
        self.client.sendall(str(encrypted_aes_key).encode('utf-8'))

        # Initialize AES cryptor
        self.aes_cryptor = AES(self.key_bytes)

    def close(self):
        if self.client:
            self.client.close()


if __name__ == '__main__':
    HOST, PORT = '127.0.0.1', 6500

    client = Client(HOST, PORT)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")
    
    client.exchange_keys()
    print("Key exchange completed and AES cryptor initialized.")

    intro_message = "Client has connected!"
    intro_hash = client.hash_message(intro_message)
    client.send(intro_message, intro_hash)
    print(f"Sent message: {intro_message}")

    while True:
        try:
            received_data = client.receive()
            received_message, received_hash = received_data.split("|")

            recalculated_hash = client.hash_message(received_message)
            if recalculated_hash != received_hash:
                print("Warning: Message integrity was compromised.")
                break

            print(f"Received message: {received_message}, Hash: {received_hash}")

            if received_message.lower() == 'end chat':
                print("Chat ended by server.")
                break

            # Send a new message
            message_to_send = input("You: ")
            message_hash = client.hash_message(message_to_send)
            client.send(message_to_send, message_hash)

            if message_to_send.lower() == 'end chat':
                print("Chat ended by client.")
                break

        except ValueError:
            print("Error: Received data format is incorrect.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            break

    client.close()
