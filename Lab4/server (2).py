import socket
from rsa import RSAEncryptor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.client = None
        
        # Generate RSA key pair
        self.rsa_cryptor = RSAEncryptor()

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)

    def accept(self):
        self.client, addr = self.server.accept()
        return addr

    def send_public_key(self):
        # Send the public key to the client
        public_key_pem = self.rsa_cryptor.serialize_public_key()
        self.client.sendall(public_key_pem)

    def receive(self, buffer_size=1024):
        encrypted_message = self.client.recv(buffer_size)
        decrypted_message = self.rsa_cryptor.decrypt(encrypted_message)

        try:
            message, hash_value = decrypted_message.split("|")
        except ValueError:
            print("Error: Message format is incorrect.")
            return None, None  # Safely handle the error

        return message, hash_value

    def send(self, message: str, hash_value: str):
        message_with_hash = message + "|" + hash_value
        encrypted_message = self.rsa_cryptor.encrypt(message_with_hash)
        self.client.sendall(encrypted_message)

    def hash_message(self, message: str) -> str:
        digest = hashes.Hash(hashes.SHA256())
        combined = message.encode('ascii')
        digest.update(combined)
        return digest.finalize().hex()

    def close(self):
        self.client.close()
        self.server.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.56.1', 65000

    # Initialize server and generate the RSA key pair
    server = Server(HOST, PORT)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    # Send the public key to the client
    server.send_public_key()

    while True:
        received_message, received_hash = server.receive()

        if not received_message:  # Handle case when the message format is incorrect
            print("Failed to receive a valid message.")
            break

        recalculated_hash = server.hash_message(received_message)

        if recalculated_hash != received_hash:
            print("Warning: Message integrity check failed!")
            break
        else:
            print(f"Message received: {received_message}, received hash: {received_hash}")

        if received_message.lower() == 'end chat':
            print("Chat ended by client.")
            break

    server.close()
