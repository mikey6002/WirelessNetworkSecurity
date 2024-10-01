import socket
from aes import AES
import hashlib

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
        decrypted_message = aes.decrypt(data)
        
        # Split the message and hash
        try:
            message, received_hash = decrypted_message.split("||")
            # Verify the integrity by comparing the hashes
            computed_hash = hashlib.sha256(message.encode()).hexdigest()
            if computed_hash == received_hash:
                print("[SERVER] Message integrity verified.")
            else:
                print("[SERVER] Message integrity compromised!")
        except ValueError:
            message = decrypted_message
            print("[SERVER] No hash received to verify integrity.")
        
        return message
    
    def send(self, message: str, key: bytes):
        # Hash the message
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        message_with_hash = f"{message}||{message_hash}"  # Append hash to message
        
        aes = AES(key)  # Create a new AES instance for encryption
        encrypted_message = aes.encrypt(message_with_hash)  # Encrypt the message
        self.client.sendall(encrypted_message)

    def close(self):
        self.client.close()
        self.server.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.1.7', 65000  # change ports

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
        print(f"\\n[CLIENT] {message}")

        msg = input("[SERVER] Enter message (type 'exit' to quit): ")
        
        if msg.lower() == "exit":
            print("[SERVER] Ending chat...")
            server.send(msg, key)
            break
        
        #send message to client
        server.send(msg, key) 
        print(f"[SERVER] sent to client: {msg}")

    server.close()
