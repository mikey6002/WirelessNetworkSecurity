import socket
from rsa import RSA
from CA import CA
from hashlib import sha256


class Server:
    def __init__(self, host, port, ca):
        self.host = host
        self.port = port
        self.server = None
        self.client = None

        self.rsa = RSA(65537)  # Using standard public exponent
        self.public_key = (self.rsa.e, self.rsa.n)  # Public key
        self.private_key = (self.rsa.d, self.rsa.n)  # Private key
        self.client_public_key = None

        self.ca = ca  # The CA instance for signing
        self.certificate = self.ca.sign(self.public_key)  # Signed certificate
        print(f"Debug: Generated server certificate: {self.certificate}")  # Debug log

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Debug: Server started at {self.host}:{self.port}")  # Debug log

    def accept(self):
        self.client, addr = self.server.accept()
        print(f"Debug: Accepted connection from {addr}")  # Debug log
        return addr

    def exchange_keys(self):
        try:
            # Send the server's signed certificate to the client
            certificate_str = f"{self.certificate['server_public_key'][0]}|{self.certificate['server_public_key'][1]}|{self.certificate['issuer']}|{self.certificate['signature']}"
            print(f"Debug: Sending server certificate: {certificate_str}")  # Debug log
            self.client.sendall(certificate_str.encode('utf-8'))

            # Receive the client's public key
            client_key_data = self.client.recv(1024).decode('utf-8')
            print(f"Debug: Received client key data: {client_key_data}")  # Debug log

            if not client_key_data.strip():
                print("Debug: Received empty client key data. Closing connection.")  # Debug log
                self.client.close()
                return
            e, n = map(int, client_key_data.split('|'))
            self.client_public_key = RSA(e, n)
            print(f"Debug: Parsed client public key: (e={e}, n={n})")  # Debug log

        except Exception as e:
            print(f"Debug: Error during key exchange: {e}")  # Debug log
            self.close()
            raise

    def receive(self, buffer_size=1024):
        try:
            data = self.client.recv(2048).decode('utf-8')
            if not data.strip():
                print("Debug: Received empty message.")  # Debug log
                return None

            message, signature = data.split("|")
            message = message.encode('utf-8')
            signature = int(signature)

            is_valid = self.client_public_key.verify(signature, message)
            print(f"Debug: Signature verification result: {is_valid}")  # Debug log

            if is_valid:
                return message.decode('utf-8')
            else:
                print("Debug: Signature verification failed.")  # Debug log
                return None
        except Exception as e:
            print(f"Debug: Error during receiving message: {e}")  # Debug log
            return None

    def send(self, message: str):
        try:
            message_bytes = message.encode('utf-8')
            signature = self.rsa.sign(message_bytes)
            data = f"{message}|{signature}"
            self.client.sendall(data.encode('utf-8'))
            print(f"Debug: Sent signed message: {message}")  # Debug log
        except socket.error as e:
            print(f"Debug: Socket error during send: {e}")  # Debug log
            self.close()
            raise

    def close(self):
        if self.client:
            print("Debug: Closing client connection.")  # Debug log
            self.client.close()
        if self.server:
            print("Debug: Closing server socket.")  # Debug log
            self.server.close()


if __name__ == '__main__':
    HOST, PORT = '192.168.1.17', 6500
    e = 65537
    # Initialize the CA
    rsa_instance = RSA(e)
    ca = CA(rsa_instance)

    # Initialize the server with the CA
    server = Server(HOST, PORT, ca)
    server.start()
    print(f"Server started at {HOST}:{PORT}")

    addr = server.accept()
    print(f"Accepted connection from {addr}")

    try:
        server.exchange_keys()

        while True:
            received_message = server.receive()
            if received_message is None:
                print("Debug: Message verification failed or message is empty.")  # Debug log
                break
            print(f"Client: {received_message}")

            if received_message.lower() == 'end chat':
                print("Debug: Chat ended by client.")  # Debug log
                break

            message_to_send = input("You: ")
            server.send(message_to_send)

            if message_to_send.lower() == 'end chat':
                print("Debug: Chat ended by server.")  # Debug log
                break

    except Exception as e:
        print(f"Debug: Error during communication: {e}")  # Debug log

    server.close()
