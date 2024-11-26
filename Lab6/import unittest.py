import unittest
from Ca import CA
from rsa import RSA

# FILE: Lab6/test_Ca.py


class TestCA(unittest.TestCase):
    def test_init(self):
        # Initialize the CA object
        ca = CA()
        
        # Check if the private_key and public_key are generated
        self.assertIsNotNone(ca.private_key, "Private key should not be None")
        self.assertIsNotNone(ca.public_key, "Public key should not be None")
        self.assertIsInstance(ca.private_key, tuple, "Private key should be a tuple")
        self.assertIsInstance(ca.public_key, tuple, "Public key should be a tuple")

if __name__ == '__main__':
    unittest.main()