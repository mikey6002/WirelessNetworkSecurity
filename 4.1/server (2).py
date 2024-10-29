
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

        self.rsa = RSA(65537)  # Using standard public exponent
        self.public_key = (self.rsa.e, self.rsa.n)  # Public key
        self.private_key = (self.rsa.d, self.rsa.n)  # Private key
        self.aes_key = None

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)

    def accept(self):
        self.client, addr = self.server.accept()
        return addr
    
    def receive(self, buffer_size=1024):
        encrypted_message = self.client.recv(buffer_size)
        cryptor = AES(self.key_bytes)  # Create a new AES instance
        decrypted_message = cryptor.decrypt(encrypted_message)
        return decrypted_message
    
    def send(self, message: str, hash_value: str):
        message_with_hash = message + "|" + hash_value
        cryptor = AES(self.key_bytes)  # Create a new AES instance
        encrypted_message = cryptor.encrypt(message_with_hash)
        self.client.sendall(encrypted_message)

    
    def hash_message(self, message: str, key: bytes) -> str:  #take both message as well as the key from file 
        digest = hashes.Hash(hashes.SHA256())
        combined = message.encode('ascii') + key
        digest.update(combined)
        return digest.finalize().hex()

    def exchange_keys(self):
        # Send public key to client
        self.client.sendall(f"{self.public_key[0]}|{self.public_key[1]}".encode('utf-8'))

        # Receive encrypted AES key from client
        encrypted_aes_key = int(self.client.recv(1024).decode('utf-8'))
        print(f"Received encrypted AES key as integer: {encrypted_aes_key}")
        
        self.aes_key = self.rsa.decrypt(encrypted_aes_key) 
        print(f"Decrypted AES key as integer (bit length: {self.aes_key.bit_length()}): {self.aes_key}")
        
        self.key_bytes = self.aes_key.to_bytes(32, byteorder='big')
        print(f"Decrypted AES key (in bytes): {self.key_bytes}")
        
        return self.key_bytes
    
    def close(self):
        self.client.close()
        self.server.close()


if __name__ == '__main__':
    HOST, PORT = '127.0.0.1', 6500

    server = Server(HOST, PORT)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    key_bytes = server.exchange_keys()
    print("key bytes: ")
    print(key_bytes)
    
    

    while True:
        
             # Wait for a message
            received_data = server.receive()
            try:
                received_message, received_hash = received_data.split("|") #split data into two strings
            except ValueError:
                print("Error: Received data format is incorrect.")
                break

           
            recalculated_hash = server.hash_message(received_message, key_bytes) #orignal message hashed with key now should be the same as the recieved hash
        
            if recalculated_hash != received_hash:
                print("Warning: Message integrity check failed!")
                break
            else:
                #message integrity verified
                print(f"meassge recieved: {received_message}, recieved hash: {received_hash}")

            if received_message.lower() == 'end chat':
                print("Chat ended by client.")
                break
        
    
            
        

            # read for message
            message_to_send = input("You: ")
            message_hash = server.hash_message(message_to_send, key_bytes) #hash message and key together for signature
            server.send(message_to_send, message_hash)

    

            # terminate if sent message is "end chat"
            if message_to_send.lower() == 'end chat':
                print("Chat ended by server.")
                break

    

    server.close()
    