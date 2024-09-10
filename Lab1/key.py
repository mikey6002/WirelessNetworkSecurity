
import random



class Key:
    """
    A simple key class that generates, reads, and writes keys.
    """

    def __init__(self):
        # do we need to initialize anything?
        pass
        #assert NotImplementedError # remove this line after your implementation

    def gen(self, key_len: int) -> bytes:
        # TODO: generate a random key
        self.key = bytes([random.randint(0, 255) for _ in range(key_len // 8)])
        return self.key
    
       #assert NotImplementedError # remove this line after your implementation
    
    def read(self, key_file: str) -> bytes:
        # TODO: read key from file
        with open(key_file, 'rb') as file:
            self.read_key = file.read()
        return self.read_key
        #assert NotImplementedError # remove this line after your implementation

    def write(self, key: bytes, key_file: str) -> None:
        # TODO: write key to file
        with open(key_file, 'wb') as file:
            file.write(key)
        #return file
        #assert NotImplementedError # remove this line after your implementation


if __name__ == '__main__':
    key = Key()
    key_len = 256

    # generate a random key
    key_bytes = key.gen(key_len)
    print("Generated key:")
    print(key_bytes.hex())

    # write the key to a file
    key_file = 'key.bytes'
    key.write(key_bytes, key_file)
    print("Key written to file:", key_file)

    # read the key from a file
    key_bytes = key.read(key_file)
    print("Read key from file:", key_file)
    print("Key:")
    print(key_bytes.hex())
