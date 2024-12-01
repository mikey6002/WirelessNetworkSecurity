import socket
from rsa import RSA
from ca import CA
import os


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = None

        # Generate client RSA keys
        self.rsa = RSA(65537)
        self.public_key = (self.rsa.e, self.rsa.n)
        self.private_key = self.rsa.d
        self.server_public_key = None
        self.trusted_ca_keys = []

    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        print("Connected to server.")

    def load_trusted_cas(self):
        # Load the trusted CA public keys from a file.
        ca_public_key_path = "ca_public_key.txt"

        # Check if the file exists
        if not os.path.exists(ca_public_key_path):
            raise FileNotFoundError(f"{ca_public_key_path} not found. Ensure the server has exported the CA public key.")

        # Load the CA's public key
        with open(ca_public_key_path, "r") as file:
            e, n = map(int, file.read().split('|'))
            self.trusted_ca_keys.append((e, n))
        print("Loaded trusted CA public keys.")


    def exchange_keys(self):
        # Receive the server's public key and certificate
        data = self.client.recv(2048).decode('utf-8').strip()
        if not data:
            raise ValueError("No server public key and certificate received.")
    
        # Extract the key string and signature
        try:
            key_string, signature = data.rsplit("|", 1)
            certificate = (key_string, int(signature))  # Ensure signature is converted to an integer
            print(f"Received server's public key and certificate: {certificate}")
        except ValueError as e:
            raise ValueError("Malformed server certificate received.") from e
    
        # Verify the server's certificate
        for ca_key in self.trusted_ca_keys:
            ca_rsa = RSA(e=ca_key[0], n=ca_key[1])
            if ca_rsa.verify(certificate[1], certificate[0].encode('utf-8')):
                print("Certificate verified successfully.")
                e, n = map(int, key_string.split('|'))
                self.server_public_key = RSA(e, n)
                
                # Send the client's public key to the server
                client_key = f"{self.public_key[0]}|{self.public_key[1]}"
                print(f"Sending client's public key: {client_key}")
                self.client.sendall(client_key.encode('utf-8'))
                return True
    
        print("Certificate verification failed. Terminating connection.")
        self.client.close()
        return False




    
        
    def send(self, message: str):
        message_bytes = message.encode('utf-8')
        signature = self.rsa.sign(message_bytes)
        self.client.sendall(f"{message}|{signature}".encode('utf-8'))

    def receive(self):
        data = self.client.recv(2048).decode('utf-8')
        message, signature = data.rsplit("|", 1)
        signature = int(signature)

        if self.server_public_key.verify(signature, message.encode('utf-8')):
            print("Signature verified successfully.")
            return message
        else:
            print("Signature verification failed.")
            return None

    def close(self):
        self.client.close()

def main():
    HOST, PORT = '192.168.1.17', 9999
    client = Client(HOST, PORT)
    client.connect()
    client.load_trusted_cas()

    if not client.exchange_keys():
        print("Connection terminated due to certificate verification failure.")
        return

    while True:
        # Send a message to the server
        message = input("You (Client): ")
        client.send(message)
        if message.lower() == "end chat":
            print("Chat ended by client.")
            break

        # Receive a reply from the server
        reply = client.receive()
        if not reply:
            print("No reply received. Server may have disconnected.")
            break
        if reply.lower() == "end chat":
            print("Chat ended by server.")
            break

        print(f"Server: {reply}")

    client.close()


if __name__ == "__main__":
    main()
