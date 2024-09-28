import socket
from aes import AES


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

    def send(self, message: str, key: bytes):
        aes = AES(key)  # create a AES instance
        encrypted_message = aes.encrypt(message)  # Encrypt the message
        self.client.sendall(encrypted_message)

    def receive(self, key: bytes):
        data = self.client.recv(1024)
        aes = AES(key) # create a AES instance
        return aes.decrypt(data)

    def close(self):
        self.client.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.56.1', 65000  # change ports
    
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
