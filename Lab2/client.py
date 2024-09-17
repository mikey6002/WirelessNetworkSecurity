
import socket


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
    HOST, PORT = '127.0.0.1', 9999

    client = Client(HOST, PORT)
    client.connect()
    print(f"Connected to server at {HOST}:{PORT}")

    message = "Hello from client!"
    client.send(message)
    print(f"Sent message: {message}")

    response = client.receive()
    print(f"Received response: {response.decode('ascii')}")

    #looping client

    client.close()