
import socket


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
    HOST, PORT = '127.0.0.1', 9999 # change ports

    server = Server(HOST, PORT)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    message = server.receive()
    print(f"Received message: {message.decode('ascii')}")

    server.send("Hello from server!")

    server.close()
    