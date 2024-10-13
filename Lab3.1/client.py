
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aes import AES
from key import Key


class Client:
    def __init__(self, host, port, key_str):
        self.host = host
        self.port = port
        self.key_bytes = key_bytes

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

    def close(self):
        self.client.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.56.1', 65000

    #initalize jey object
    key = Key()
    key_bytes = key.read('key.bytes')


    client = Client(HOST, PORT, key_bytes)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")

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