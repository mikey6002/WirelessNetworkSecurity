import socket
from aes import AES
import hashlib

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

    def send(self, message: str, key: bytes):
        # Hash the message
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        message_with_hash = f"{message}||{message_hash}"  # append adding hash to the end of message
        
        aes = AES(key)  # create a AES instance
        encrypted_message = aes.encrypt(message_with_hash)  # Encrypt the message
        self.client.sendall(encrypted_message)

    def receive(self, key: bytes) -> str:
        data = self.client.recv(1024)
        aes = AES(key) # create a AES instance
        decrypted_message = aes.decrypt(data)
        
        # try and split the message and hash
        try:
            message, received_hash = decrypted_message.split("||")
            # vrify integrity by comparing the hashes of the messages
            computed_hash = hashlib.sha256(message.encode()).hexdigest()
            if computed_hash == received_hash:
                print("[CLIENT] Message integrity is all clear.")
            else:
                print("[CLIENT] Message compromised!")
        except ValueError:
            message = decrypted_message
            print("[CLIENT] No hash received to verify integrity.")
        
        return message

    def close(self):
        self.client.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.1.7', 65000  # change ports
    
    with open("key.bytes", "rb") as key_file:
        key = key_file.read()
        
    client = Client(HOST, PORT)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")

    message = "Hello from client!"
    client.send(message, key)
    print(f"Sent message: {message}")

    response = client.receive(key)
    print(f"Received response: {response}")

    # looping client
    while True:
        message = input("Enter message (type 'exit' to quit): ")

        if message.lower() == "exit":
            print("Ending chat...")
            client.send(message, key)
            break
        
        client.send(message, key)
        print(f"Sent message: {message}")

        response = client.receive(key)
        print(f"Received response from server: {response}")

    client.close()
