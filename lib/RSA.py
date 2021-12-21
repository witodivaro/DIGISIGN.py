from gmpy2 import is_prime, invert, powmod
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def get_random_prime(size):
    prime_bytes = get_random_bytes(size // 8)
    prime = int.from_bytes(prime_bytes, 'big')
    
    while (True):
        if (is_prime(prime)):
            return prime
        prime += 1

def generate(size = 2048):
    p = get_random_prime(size - 10)
    q = get_random_prime(size + 10)
    
    N = p * q
    totient = (p - 1) * (q - 1)
    
    e = 65537
    d = invert(e, totient)
    
    return (e, d, N)
    
def sign(d, N, message):
    """Signs a message with a RSA decryption key

    Args:
        d (int): RSA Decryption Key
        N (int): RSA Modulus
        message (string): Hex string
    """
    
    size = N.bit_length()
    byte_size = size // 8
    
    message_bytes = bytes.fromhex(message)
    message_digest = SHA256.new(message_bytes).digest()
    
    padded_message_digest = message_digest.ljust(byte_size, b'0')
    message_digest_int = int.from_bytes(padded_message_digest, 'big')

    signature_int = powmod(message_digest_int, d, N)
    
    hexed_signature = hex(signature_int)[2:]
    
    if (len(hexed_signature) % 2 != 0):
        hexed_signature = "0" + hexed_signature
    
    return hexed_signature
    
def verify(e, N, message, tag):
    """Verifies a message with a RSA encryption key

    Args:
        e (int): RSA encryption key
        N (int): RSA modulus
        message (string): Hex string
        tag (string): Hex signature to verify
    """
    
    size = N.bit_length()
    byte_size = size // 8
    
    message_bytes = bytes.fromhex(message)
    message_digest = SHA256.new(message_bytes).digest()
    
    padded_message_digest = message_digest.ljust(byte_size, b'0')
    message_digest_int = int.from_bytes(padded_message_digest, 'big')
    
    tag_bytes = bytes.fromhex(tag)
    tag_int = int.from_bytes(tag_bytes, 'big')
    signature_message_digest_int = powmod(tag_int, e, N)
    
    
    return signature_message_digest_int == message_digest_int
    