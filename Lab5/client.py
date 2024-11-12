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
        self.client = None

        self.rsa = RSA(65537)  
        self.public_key = (self.rsa.e, self.rsa.n)
        self.private_key = self.rsa.d
        self.server_public_key = None 
       
        

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

    def send(self, message: str):
        # Sign the message with the client's private key
        message_bytes = message.encode('utf-8')
        signature = self.rsa.sign(message_bytes)
        data = f"{message}|{signature}"
        self.client.sendall(data.encode('utf-8'))
        print("Sent signed message to server.")

    def receive(self, buffer_size=1024):
        # Receive a message and its signature
        data = self.client.recv(2048).decode('utf-8')
        message, signature = data.split("|")
        message = message.encode('utf-8')
        signature = int(signature)

        # Verify the signature using the server's public key
        is_valid = self.server_public_key.verify(signature, message)
        if is_valid:
            print("Signature verified successfully.")
            return message.decode('utf-8')
        else:
            print("Signature verification failed.")
            return None

    def hash_message(self, message: str, key: bytes) -> str:
        """Generate and sign HMAC."""
        digest = hashes.Hash(hashes.SHA256())
        combined = message.encode('ascii') + key
        digest.update(combined)
        hmac = digest.finalize()
        
        # Sign the HMAC with the client's private key
        signature = self.rsa.sign(hmac)
        return f"{hmac.hex()}|{signature}"

    def verify_hmac(self, hmac_signature: str) -> bool:
        """Verify HMAC using the server's public key."""
        hmac, signature = hmac_signature.split("|")
        hmac = bytes.fromhex(hmac)
        signature = int(signature)
        return self.server_public_key.verify(signature, hmac)


    def exchange_keys(self):
        # Receive the server's public key
        server_key_data = self.client.recv(1024).decode('utf-8')
        e, n = map(int, server_key_data.split('|'))
        self.server_public_key = RSA(e, n)
        print("Received server's public key.")

        # Send the client's public key to the server
        self.client.sendall(f"{self.public_key[0]}|{self.public_key[1]}".encode('utf-8'))
        print("Sent client's public key to server.")

    def close(self):
        self.client.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.56.1', 9999


    client = Client(HOST, PORT)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")
    client.exchange_keys()
   

    intro = "Client has connected!"
    client.send(intro)
    print(f"Sent message: {intro}")

    while True:
            received_message = client.receive()
            if received_message is None:
                print("Message verification failed or message is empty.")
                break
            print(f"Client: {received_message}")


            if received_message.lower() == 'end chat':
                print("Chat ended by server.")
                break
        
    
            # read for message
            message_to_send = input("You: ")
            client.send(message_to_send)

    
            # terminate if sent message is "end chat"
            if message_to_send.lower() == 'end chat':
                print("Chat ended by client.")
                break

    client.close()