
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aes import AES
from key import Key
from rsa import RSA


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.key_bytes = None

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

    def send(self, message: str, hash_value: str):
        message_with_hash = message + "|" + hash_value
        cryptor = AES(self.key_bytes)  # Create a new AES instance
        encrypted_message = cryptor.encrypt(message_with_hash)
        self.client.sendall(encrypted_message)

    def receive(self, buffer_size=1024):
        encrypted_message = self.client.recv(buffer_size)
        cryptor = AES(self.key_bytes)  # Create a new AES instance
        decrypted_message = cryptor.decrypt(encrypted_message)
        return decrypted_message

    def hash_message(self, message: str, key: bytes) -> str:  #take both message as well as the key from file 
        digest = hashes.Hash(hashes.SHA256())
        combined = message.encode('ascii') + key
        digest.update(combined)
        return digest.finalize().hex()

    def exchange_keys(self):
        # Receive the server's public key
        public_key = self.client.recv(1024).decode('utf-8')
        e, n = [int(x) for x in public_key.split('|')]
        rsa = RSA(e, n)  # Recreate RSA object with servers e and n

        # Generate AES key
        key = Key()
        self.aes_key = key.gen(256)
        print(f"Generated AES key (in bytes): {self.aes_key}")

        # Encrypt AES key with the server's public key
        aes_key_as_int = int.from_bytes(self.aes_key, byteorder='big')
        print(f"AES key as integer (before encryption): {aes_key_as_int} (bit length: {aes_key_as_int.bit_length()})")
        encrypted_aes_key = rsa.encrypt(aes_key_as_int)
        print(f"AES key as integer (after encryption): {encrypted_aes_key} (bit length: {encrypted_aes_key.bit_length()})")
        
        self.client.sendall(str(encrypted_aes_key).encode('utf-8'))
        self.key_bytes = self.aes_key
        return self.key_bytes

    def close(self):
        self.client.close()


if __name__ == '__main__':
    HOST, PORT = '127.0.0.1', 6500


    client = Client(HOST, PORT)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")
    key_bytes = client.exchange_keys()
    print("key bytes: ")
    print(key_bytes)

    intro = "Client has connected!"
    intro_hash = client.hash_message(intro, key_bytes)
    client.send(intro, intro_hash)
    print(f"Sent message: {intro}")

    while True:
        received_data = client.receive()

        try:
            received_message, received_hash = received_data.split("|")
        except ValueError:
                print("Error: Received data format is incorrect.")
                break
            
            
        recalculated_hash = client.hash_message(received_message, key_bytes)
            
        if recalculated_hash != received_hash:
            print("Warning: Message integrity was comprimised")
            break
        else:
            #Message integrity verified.
            print(f"meaasge recieved: {received_message}, recieved hash: {received_hash}")

        if received_message.lower() == 'end chat':
            print("Chat ended by server.")
            break

        

        message_to_send = input("you: ")
        message_hash = client.hash_message(message_to_send, key_bytes)
        client.send(message_to_send, message_hash)

        if message_to_send.lower() == 'end chat':
            print("Chat ended by client.")
            break

        

    client.close()