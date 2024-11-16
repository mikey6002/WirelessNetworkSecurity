
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rsa import RSA



class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.client = None
        self.key_bytes = None

        self.rsa = RSA(65537)  # Using standard public exponent
        self.public_key = (self.rsa.e, self.rsa.n)  # Public key
        self.private_key = (self.rsa.d, self.rsa.n)  # Private key
        self.aes_key = None
        self.client_public_key = None

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)

    def accept(self):
        self.client, addr = self.server.accept()
        return addr
    
    def receive(self, buffer_size=1024):
        # Receive a message and its signature
        data = self.client.recv(2048).decode('utf-8')# bytes to string 
        message, signature = data.split("|") # split recieved data into message and signature
        message = message.encode('utf-8') # encode message into bytes (sig req original message) 
        signature = int(signature)

        # Verify the signature using the client's public key
        is_valid = self.client_public_key.verify(signature, message)
        if is_valid:
            print("Signature verified successfully.")
            return message.decode('utf-8')
        else:
            print("Signature verification failed.")
            return None
    
    def send(self, message: str):
        # Sign the message with the server's private key
        message_bytes = message.encode('utf-8')
        signature = self.rsa.sign(message_bytes)
        data = f"{message}|{signature}"
        self.client.sendall(data.encode('utf-8'))
        print("Sent signed message to client.")

    def exchange_keys(self):
         # Send the server's public key to the client
        self.client.sendall(f"{self.public_key[0]}|{self.public_key[1]}".encode('utf-8'))
        print("Sent server's public key to client.")

        # Receive the client's public key
        client_key_data = self.client.recv(1024).decode('utf-8')
        e, n = map(int, client_key_data.split('|'))
        self.client_public_key = RSA(e, n)
        print("Received client's public key.")

    
    def close(self):
        self.client.close()
        self.server.close()


if __name__ == '__main__':
    HOST, PORT = '10.109.21.177', 9999

    server = Server(HOST, PORT)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

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
        
    
            # read for message
            message_to_send = input("You: ")
            server.send(message_to_send)

    
            # terminate if sent message is "end chat"
            if message_to_send.lower() == 'end chat':
                print("Chat ended by server.")
                break

    

    server.close()
    