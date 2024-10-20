import socket
from rsa import RSAEncryptor
from aes import AES  # Import the AES class for decryption

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.client = None
        self.rsa_cryptor = RSAEncryptor()  # RSA for key exchange
        self.aes_key = None  # This will hold the AES key for message encryption

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Server is listening on {self.host}:{self.port}")

    def accept(self):
        self.client, addr = self.server.accept()
        return addr

    def send_public_key(self):
        # Send the public key to the client
        public_key_pem = self.rsa_cryptor.serialize_public_key()
        self.client.sendall(public_key_pem)

    def receive_aes_key(self):
        encrypted_aes_key = self.client.recv(1024)  # Adjust buffer size as needed
        # Decrypt the AES key using the server's private key
        self.aes_key = self.rsa_cryptor.decrypt(encrypted_aes_key)  # This will return bytes
        print("AES key received and decrypted.")

    def send(self, message: str):
        if not self.aes_key:
            raise ValueError("AES key has not been set. Cannot send message.")

        aes_cryptor = AES(self.aes_key)
        encrypted_message = aes_cryptor.encrypt(message)
        self.client.sendall(encrypted_message)

    def receive(self, buffer_size=1024):
        encrypted_message = self.client.recv(buffer_size)
        aes_cryptor = AES(self.aes_key)  # Use the AES key for decryption
        decrypted_message = aes_cryptor.decrypt(encrypted_message)
        return decrypted_message

    def close(self):
        self.client.close()
        self.server.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.1.7', 65000  # Change to the correct IP address for your server

    # Initialize server and generate the RSA key pair
    server = Server(HOST, PORT)
    server.start()

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    # Send the public key to the client
    server.send_public_key()

    # Receive the AES key from the client
    server.receive_aes_key()

    while True:
        # Receive message
        received_message = server.receive()
        if not received_message:  # Handle case when the message is empty
            print("Failed to receive a valid message.")
            break

        print(f"Message received: {received_message}")

        if received_message.lower() == 'end chat':
            print("Chat ended by client.")
            break

    server.close()
