from Crypto.Cipher import AES
from hashlib import sha1
from itertools import cycle

class InvalidPaddingError(Exception):
    """Custom exception for handling invalid padding."""
    pass

# Utility function for breaking data into fixed-size chunks
def chunks(data, size):
    """Splits data into chunks of the specified size."""
    return [data[i:i + size] for i in range(0, len(data), size)]

def pkcs7_pad(message, block_size):
    """Pads the input message using PKCS#7 padding to fit the block size."""
    pad_len = block_size - (len(message) % block_size)
    return message + bytes([pad_len] * pad_len)

def pkcs7_unpad(message, block_size):
    """Removes PKCS#7 padding from a message."""
    pad_len = message[-1]
    if pad_len > block_size or message[-pad_len:] != bytes([pad_len] * pad_len):
        raise InvalidPaddingError("Invalid PKCS#7 padding.")
    return message[:-pad_len]

def fixed_xor(buffer1, buffer2):
    """Performs XOR between two byte buffers of equal length."""
    return bytes(b1 ^ b2 for b1, b2 in zip(buffer1, buffer2))

def repeating_key_xor(message, key):
    """Encrypts/decrypts a message using repeating-key XOR."""
    return bytes(m ^ k for m, k in zip(message, cycle(key)))

def aes_ecb_encrypt(plaintext, key):
    """Encrypts plaintext using AES in ECB mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(plaintext, AES.block_size))

def aes_ecb_decrypt(ciphertext, key):
    """Decrypts ciphertext using AES in ECB mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(ciphertext), AES.block_size)

def aes_cbc_encrypt(plaintext, key, iv):
    """Encrypts plaintext using AES in CBC mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    ciphertext = b""
    for block in chunks(pkcs7_pad(plaintext, AES.block_size), AES.block_size):
        xor_block = fixed_xor(block, prev_block)
        encrypted_block = cipher.encrypt(xor_block)
        ciphertext += encrypted_block
        prev_block = encrypted_block
    return ciphertext

def aes_cbc_decrypt(ciphertext, key, iv):
    """Decrypts ciphertext using AES in CBC mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    plaintext = b""
    for block in chunks(ciphertext, AES.block_size):
        decrypted_block = fixed_xor(prev_block, cipher.decrypt(block))
        plaintext += decrypted_block
        prev_block = block
    return pkcs7_unpad(plaintext, AES.block_size)

def increment_nonce(nonce):
    """Increments a nonce (in bytes) by treating it as a big-endian integer."""
    nonce = bytearray(nonce)
    for i in reversed(range(len(nonce))):
        if nonce[i] == 255:
            nonce[i] = 0
        else:
            nonce[i] += 1
            break
    return bytes(nonce)

def ctr_crypt(message, cipher, nonce):
    """Encrypts/decrypts a message using CTR mode."""
    encrypted_msg = b""
    for block in chunks(message, cipher.block_size):
        keystream = cipher.encrypt(nonce)
        encrypted_msg += fixed_xor(block, keystream[:len(block)])
        nonce = increment_nonce(nonce)
    return encrypted_msg

def aes_ctr_crypt(message, key, nonce):
    """Encrypts/decrypts a message using AES in CTR mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    return ctr_crypt(message, cipher, nonce)

def detect_ecb(ciphertext, block_size):
    """Detects if a ciphertext is likely encrypted using ECB mode."""
    blocks = chunks(ciphertext, block_size)
    # Return True if any block is repeated, indicating ECB mode
    return any(blocks.count(block) > 1 for block in blocks)

def hmac(hash_function):
    """Implements HMAC using a given hash function."""
    def _hmac(key, message):
        block_size = hash_function().block_size
        if len(key) > block_size:
            key = hash_function(key).digest()
        elif len(key) < block_size:
            key += b'\x00' * (block_size - len(key))

        o_key_pad = fixed_xor(key, b'\x5c' * block_size)
        i_key_pad = fixed_xor(key, b'\x36' * block_size)

        return hash_function(o_key_pad + hash_function(i_key_pad + message).digest()).digest()
    return _hmac

sha1_hmac = hmac(sha1)
