import socket
from aes import AES


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.client = None

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)

    def accept(self):
        self.client, addr = self.server.accept()
        return addr
    
    def receive(self, key: bytes) -> str:
        data = self.client.recv(1024)
        aes = AES(key)  # Create a new AES instance for decryption
        return aes.decrypt(data)
    
    def send(self, message: str, key: bytes):
        aes = AES(key)  # Create a new AES instance for encryption
        encrypted_message = aes.encrypt(message)  # Encrypt the message
        self.client.sendall(encrypted_message)

    def close(self):
        self.client.close()
        self.server.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.56.1', 65000  # change ports

    with open("key.bytes", "rb") as key_file:
        key = key_file.read()
        
    server = Server(HOST, PORT)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    message = server.receive(key)
    print(f"Received message: {message}")

    server.send("Hello from server!", key)

    # looping chat
    while True:
        message = server.receive(key)
        print(f"\n[CLIENT] {message}")

        msg = input("[SERVER] Enter message (type 'exit' to quit): ")
        
        if msg.lower() == "exit":
            print("[SERVER] Ending chat...")
            server.send(msg, key)
            break
        
        #send message to client
        server.send(msg, key) 
        print(f"[SERVER] sent to client: {msg}")

    server.close()
