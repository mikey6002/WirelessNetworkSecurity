import socket
from cryptography.hazmat.primitives import serialization
from rsa import RSAEncryptor
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = None
        self.server_public_key = None  # Will hold the server's public key
        self.rsa_cryptor = RSAEncryptor()  # Client will have its own key pair for decryption

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

        # Receive server's public key upon connection
        public_key_pem = self.client.recv(1024)  # Adjust buffer size as needed
        self.server_public_key = serialization.load_pem_public_key(public_key_pem)

    def send(self, message: str, message_hash: str):
        # Combine the message and hash
        message_with_hash = message + "|" + message_hash
        
        # Encrypt the combined message using the server's public key
        ciphertext = self.server_public_key.encrypt(
            message_with_hash.encode('ascii'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.client.sendall(ciphertext)

    def receive(self, buffer_size=1024):
        encrypted_message = self.client.recv(buffer_size)
        decrypted_message = self.rsa_cryptor.decrypt(encrypted_message)
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

    while True:
        # Send message
        message_to_send = input("You: ")
        message_hash = client.hash_message(message_to_send)
        client.send(message_to_send, message_hash)

        if message_to_send.lower() == 'end chat':
            print("Chat ended by client.")
            break

        # Receive message
        received_data = client.receive()
        try:
            received_message, received_hash = received_data.split("|")
        except ValueError:
            print("Error: Received data format is incorrect.")
            break

        recalculated_hash = client.hash_message(received_message)
        if recalculated_hash != received_hash:
            print("Warning: Message integrity was compromised!")
            break
        else:
            # Message integrity verified
            print(f"Message received: {received_message}, received hash: {received_hash}")

        if received_message.lower() == 'end chat':
            print("Chat ended by server.")
            break

    client.close()
