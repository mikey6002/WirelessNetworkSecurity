
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aes import AES
from key import Key



class Server:
    def __init__(self, host, port, cryptor):
        self.host = host
        self.port = port
        self.server = None
        self.client = None
        self.cryptor = cryptor
        self.key_bytes = key_bytes

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
    
    def close(self):
        self.client.close()
        self.server.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.56.1', 65000

   # Initialize key object and read the key
    key = Key()
    key_bytes = key.read('key.bytes')

    # Initialize server with key bytes
    server = Server(HOST, PORT, key_bytes)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    

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
    