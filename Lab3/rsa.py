import random
import math 


small_primes = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 
    37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113, 127
]

def is_prime(n):
    #chck prime number
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime():
    #get random number
    return random.choice(small_primes)


#euclidean alogorithm gcd compute 'd'
def mod_inverse(a, m):#e,phi
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a) #recursive step to keep finding gcd
            return (g, x - (b // a) * y, y)

    g, x, _ = egcd(a, m) #find GCD 
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keypair():
    #generate keys
    p = generate_prime()
    q = generate_prime()
    while p == q: #make sure p q not the same
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 5  #small e 
    while math.gcd(e, phi) != 1: # is e co prime 
        e += 2  # Increment e to find a valid one
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def mod_pow(base, exponent, modulus):
    #modulat expnentiation
    result = 1
    base = base % modulus #reduce base if larger than mod
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1 # right shift
        base = (base * base) % modulus
    return result

def encrypt(public_key, plaintext):
    e, n = public_key
    encrypted_message = []
    
    for char in plaintext:
       # ascii value of the char
        ascii_value = ord(char)
        
        # Encrypt the character using modular exponentiation
        encrypted_char = mod_pow(ascii_value, e, n)
        
        # Add the encrypted character to the result list
        encrypted_message.append(encrypted_char)
    
    return encrypted_message

def decrypt(private_key, ciphertext):
    d, n = private_key
    decrypted_message = []
    
  
    for encrypted_char in ciphertext:
        # Decrypt number using modular exponentiation
        decrypted_ascii = mod_pow(encrypted_char, d, n)
        
        # Convert decrypted ASCII value back to a character
        decrypted_char = chr(decrypted_ascii)
        
        #decrypted character to the result list
        decrypted_message.append(decrypted_char)
    
    # Join the list of characters into a single string
    return ''.join(decrypted_message)


if __name__ == "__main__":
    public_key, private_key = generate_keypair()
    message = "Hello World"
    encrypted_msg = encrypt(public_key, message)
    decrypted_msg = decrypt(private_key, encrypted_msg)

    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted_msg}")
    print(f"Decrypted message: {decrypted_msg}")
