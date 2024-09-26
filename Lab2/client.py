
import socket
from aes import AES


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

    def send(self, message: str):
        message_bytes = bytes(message, 'ascii')
        self.client.sendall(message_bytes)

    def receive(self):
        return self.client.recv(1024)

    def close(self):
        self.client.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.56.1', 65000 # change ports
    
    with open("key.bytes", "rb") as key_file:
        key = key_file.read()
        
    aes = AES(key)

    client = Client(HOST, PORT)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")

    message = "Hello from client!"
    client.send(message)
    print(f"Sent message: {message}")

    response = client.receive()
    print(f"Received response: {response.decode('ascii')}")
    
    

    #looping client
    while True:
        # User input
        message = input("Enter message (type 'exit' to quit): ")

        if message.lower() == "exit":
            print("Ending chat...")
            client.send(message)
            break
        
        #encrypt and send
        encrypted_message = aes.encrypt(message)
        client.send(encrypted_message)
        ##client.send(message)
        print(f"Sent message: {message}")
        
        
        # receive the encrypted response
        encrypted_response = client.receive()

        
        # Decrypt the received response
        decrypted_response = aes.decrypt(encrypted_response)
        print(f"Received decrypted response from server: {decrypted_response}")
        ##response = client.receive()
        ##print(f"Received response from server: {response}")

    # Close the connection
    client.close()