'''
ChaCha20 Stream Cipher Implementation

Description:
    This module provides a microython implementation of the ChaCha20 
    encryption algorithm, as defined in RFC 7539.

Author:
    MicroControleurMonde

References:
    - RFC 7539: https://tools.ietf.org/html/rfc7539
    - Original design by Daniel J. Bernstein

Usage:
    key = bytes(32)    # 256-bit key
    nonce = bytes(8)   # 64-bit nonce
    
    cipher = ChaCha20(key, nonce)
    ciphertext = cipher.encrypt(plaintext)
    
    # Re-initialize for decryption
    decipher = ChaCha20(key, nonce)
    plaintext = decipher.decrypt(ciphertext)

For educationnal purposes only
'''

import struct

def rotl32(v, c):
    '''
    Rotate a 32-bit unsigned integer v to the left by c bits.
    Ensures the result stays within 32 bits by applying a mask.
    '''
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

class ChaCha20:
    def __init__(self, key, nonce):
        '''
        Initialize the ChaCha20 context with a 256-bit key and a 64-bit nonce.
        Sets up the initial state matrix (16 words).
        '''
        self.input = [0] * 16
        # Constants: "expa" "nd 3" "2-by" "te k" (Little Endian)
        self.input[0] = 0x61707865
        self.input[1] = 0x3320646e
        self.input[2] = 0x79622d32
        self.input[3] = 0x6b206574
        
        # Charger la clé
        key_ints = struct.unpack('<8I', key)
        self.input[4:12] = key_ints
        
        # Initialize the block counter to 0 (words 12 and 13)
        self.input[12] = 0
        self.input[13] = 0
        # Load the nonce (8 bytes -> 2 unsigned integers)
        nonce_ints = struct.unpack('<2I', nonce)
        self.input[14:16] = nonce_ints

    def quarter_round(self, x, a, b, c, d):
        '''
        The ChaCha20 quarter-round function.
        It performs a series of additions, XORs, and bit rotations 
        on four 32-bit words of the state at indices a, b, c, and d.
        '''        
        
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] ^= x[a]
        x[d] = rotl32(x[d], 16)
        
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] ^= x[c]
        x[b] = rotl32(x[b], 12)
        
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] ^= x[a]
        x[d] = rotl32(x[d], 8)
        
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] ^= x[c]
        x[b] = rotl32(x[b], 7)

    def chacha20_block(self):
        '''
        Generate one 64-byte key stream block.
        The function runs 10 rounds (20 column/diagonal rounds),
        adds the initial state, and increments the block counter.
        '''        
        # Work on a copy of the state
        x = self.input.copy()   
        # Perform 10 double rounds (20 single rounds total)
        for _ in range(10):
            self.quarter_round(x, 0, 4, 8, 12)
            self.quarter_round(x, 1, 5, 9, 13)
            self.quarter_round(x, 2, 6, 10, 14)
            self.quarter_round(x, 3, 7, 11, 15)
            self.quarter_round(x, 0, 5, 10, 15)
            self.quarter_round(x, 1, 6, 11, 12)
            self.quarter_round(x, 2, 7, 8, 13)
            self.quarter_round(x, 3, 4, 9, 14)
 
        # Add the initial state to the mixed state
        output = []
        for i in range(16):
            output.append((x[i] + self.input[i]) & 0xffffffff)
        
        # Increment the block counter (word 12)
        self.input[12] = (self.input[12] + 1) & 0xffffffff
        # Handle overflow to word 13 if word 16 wraps around
        if self.input[12] == 0:
            self.input[13] = (self.input[13] + 1) & 0xffffffff
        
        # Serialize the 16 words into 64 bytes
        return struct.pack('<16I', *output)

    def encrypt(self, plaintext):
        '''
        Encrypt the input plaintext using the generated key stream.
        Processes data in 64-byte blocks.
        '''
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 64):
            block = self.chacha20_block()
            for j in range(min(64, len(plaintext) - i)):
                ciphertext.append(plaintext[i+j] ^ block[j])
        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        '''
        Decrypt the input ciphertext.
        ChaCha20 is symmetric, so decryption is the same as encryption.
        '''
        return self.encrypt(ciphertext)

# Example usage
key = b'0' * 32  # Key: 256 bits (32 bytes)
nonce = b'0' * 8  # Nonce: 64 bits (8 bytes)

chacha = ChaCha20(key, nonce)
plaintext = b"Hello, ChaCha20! Essai de chiffrage & dechiffrage"
ciphertext = chacha.encrypt(plaintext)
chacha = ChaCha20(key, nonce)  # Reset the state (counter) for decryption
decrypted = chacha.decrypt(ciphertext) # Decrypt


print("Plaintext:", plaintext)
print("\nCiphertext:", ciphertext)
print("\nDecrypted:", decrypted)

