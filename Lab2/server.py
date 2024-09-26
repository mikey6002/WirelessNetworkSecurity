
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
    
    def receive(self, buffer_size=1024):
        return self.client.recv(buffer_size)
    
    def send(self, message: str):
        message_bytes = bytes(message, 'ascii')
        self.client.sendall(message_bytes)

    def close(self):
        self.client.close()
        self.server.close()


if __name__ == '__main__':
    #shared host and port
    HOST, PORT = '192.168.56.1', 65000 # change ports

    # Load the AES encryption key from key.bytes
    with open("key.bytes", "rb") as key_file:
        key = key_file.read()
        
    aes = AES(key)
    
    server = Server(HOST, PORT)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    message = server.receive()
    print(f"Received message: {message.decode('ascii')}")

    server.send("Hello from server!")

    #looping chat
    while True:
        message = server.receive()
        msg = aes.decrypt(message)
        print(f"\n[CLIENT] {msg}")
        
        msg = input("[SERVER] Enter message (type 'exit' to quit")
        msg_enc = aes.encrypt(msg)
        
        
        if message.lower() == "exit":
            print("[SERVER] Ending chat...")
            server.send(msg_enc)
            break
        
        response = "Message Recieved: "
        server.send(aes.encrypt(response))
        #server.send(response)
        print(f"[SERVER] sent to client: {response}")
    server.close()
    