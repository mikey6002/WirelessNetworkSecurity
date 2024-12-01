import socket
from rsa import RSA
from ca import CA

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.client = None

        # Generate server RSA keys
        self.rsa = RSA(65537)
        self.public_key = (self.rsa.e, self.rsa.n)
        self.private_key = self.rsa.d
        self.client_public_key = None

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(1)
        print("Server started, waiting for client...")

    def accept(self):
        self.client, addr = self.server.accept()
        print(f"Accepted connection from {addr}")
        return addr
    
    def exchange_keys(self, ca: CA):
        # Generate and send the server's certificate
        certificate = ca.sign(self.public_key)
        print(f"Generated certificate for server's public key: {certificate}")
        self.client.sendall(f"{certificate[0]}|{certificate[1]}".encode('utf-8'))
        print("Sent server's public key and certificate to client.")
    
        # Receive the client's public key
        try:
            client_key_data = self.client.recv(1024).decode('utf-8').strip()
            if not client_key_data:
                raise ValueError("No client public key received.")
            print(f"Received raw client key data: {client_key_data}")
            e, n = map(int, client_key_data.split('|'))
            self.client_public_key = RSA(e, n)
            print("Client's public key has been stored.")
        except Exception as e:
            print(f"Error receiving client's public key: {e}")
            raise



    def send(self, message: str):
        message_bytes = message.encode('utf-8')
        signature = self.rsa.sign(message_bytes)
        self.client.sendall(f"{message}|{signature}".encode('utf-8'))

    def receive(self):
        data = self.client.recv(2048).decode('utf-8')
        message, signature = data.rsplit("|", 1)
        signature = int(signature)

        if self.client_public_key.verify(signature, message.encode('utf-8')):
            print("Signature verified successfully.")
            return message
        else:
            print("Signature verification failed.")
            return None

    def close(self):
        self.client.close()
        self.server.close()

def main():
    HOST, PORT = '192.168.1.17', 9999

    # Initialize the Certificate Authority (CA)
    ca = CA()  # Automatically generates ca_public_key.txt
    print("Certificate Authority initialized and public key exported.")

    # Initialize the server
    server = Server(HOST, PORT)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    # Exchange keys with the client
    server.exchange_keys(ca)

    while True:
        # Receive a message from the client
        message = server.receive()
        if not message:
            print("No message received. Client may have disconnected.")
            break
        if message.lower() == "end chat":
            print("Chat ended by client.")
            break

        print(f"Client: {message}")

        # Send a reply to the client
        reply = input("You (Server): ")
        server.send(reply)
        if reply.lower() == "end chat":
            print("Chat ended by server.")
            break

    server.close()


if __name__ == "__main__":
    main()