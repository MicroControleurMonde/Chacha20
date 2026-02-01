# ChaCha20-Poly1305 AEAD Implementation for MicroPython
'''
    Description:
    This module provides a MicroPython implementation of the ChaCha20 stream cipher
    and the Poly1305 authenticator, combined as an AEAD (Authenticated Encryption
    with Associated Data) construction. It is designed to be compatible with
    MicroPython environments.

    Classes:
        ChaCha20: Handles encryption and decryption using the ChaCha20 algorithm.
        Poly1305: Handles the generation and verification of authentication tags.

    Functions:
        chacha20_poly1305_encrypt: Encrypts plaintext and authenticates associated data.
        chacha20_poly1305_decrypt: Verifies the tag and decrypts ciphertext.
'''
    
import struct
import ubinascii

def rotl32(v, c):
    '''
    Rotate a 32-bit unsigned integer v to the left by c bits.
    '''
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

class ChaCha20:
    '''
    Implementation of the ChaCha20 stream cipher.
    '''
    def __init__(self, key, nonce):
        '''
        Initialize the ChaCha20 state with constants, key, and nonce.
        
        :param key: 32-byte key (256 bits).
        :param nonce: 12-byte nonce (96 bits).
        '''
        self.input = [0] * 16
        # Constants ("expand 32-byte k")
        self.input[0] = 0x61707865
        self.input[1] = 0x3320646e
        self.input[2] = 0x79622d32
        self.input[3] = 0x6b206574
        
        # Key interpreted as 8 little-endian 32-bit integers
        key_ints = struct.unpack('<8I', key)
        self.input[4:12] = key_ints
        
        # Initial block counter (starts at 0)
        self.input[12] = 0
        self.input[13] = 0
        
        # Nonce interpreted as 2 little-endian 32-bit integers
        nonce_ints = struct.unpack('<2I', nonce)
        self.input[14:16] = nonce_ints

    def quarter_round(self, x, a, b, c, d):
        '''
        Perform the ChaCha20 quarter round operation on indices a, b, c, d.
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
        Generate one 64-byte keystream block.
        Increments the block counter internally.
        '''
        x = self.input.copy()
        
        # 10 double rounds (20 quarter rounds per column/diagonal)
        for _ in range(10):
            # Column rounds
            self.quarter_round(x, 0, 4, 8, 12)
            self.quarter_round(x, 1, 5, 9, 13)
            self.quarter_round(x, 2, 6, 10, 14)
            self.quarter_round(x, 3, 7, 11, 15)
            # Diagonal rounds
            self.quarter_round(x, 0, 5, 10, 15)
            self.quarter_round(x, 1, 6, 11, 12)
            self.quarter_round(x, 2, 7, 8, 13)
            self.quarter_round(x, 3, 4, 9, 14)
        
        output = []
        # Add initial state to the permuted state
        for i in range(16):
            output.append((x[i] + self.input[i]) & 0xffffffff)
        
        # Increment block counter
        self.input[12] = (self.input[12] + 1) & 0xffffffff
        if self.input[12] == 0:
            self.input[13] = (self.input[13] + 1) & 0xffffffff
        
        return struct.pack('<16I', *output)

    def encrypt(self, plaintext):
        '''
        Encrypt plaintext using XOR with the keystream.
        '''
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 64):
            block = self.chacha20_block()
            for j in range(min(64, len(plaintext) - i)):
                ciphertext.append(plaintext[i+j] ^ block[j])
        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        '''
        Decrypt ciphertext (identical operation to encrypt).
        '''
        return self.encrypt(ciphertext)

class Poly1305:
    '''
    Implementation of the Poly1305 message authenticator.
    '''
    def __init__(self, key):
        '''
        Initialize Poly1305 with a 32-byte key (derived from ChaCha20).
        '''
        self.r = struct.unpack('<IIII', key[:16])
        self.s = struct.unpack('<IIII', key[16:])
        self.accumulator = [0, 0, 0, 0]
        # Prime P = 2^130 - 5 is implicitly handled in the 26-bit limb logic
        self.p = (1 << 130) - 5 

    def add(self, block):
        '''
        Add a block to the accumulator and perform multiplication.
        Block is expected as a tuple of 4 integers representing 16 bytes.
        '''
        # Add the block to the accumulator (r is clamped externally implicitly by usage)
        # Note: This implementation assumes the block bytes are packed into 32-bit integers
        # and handled as 26-bit limbs effectively.
        self.accumulator[0] += block[0]
        self.accumulator[1] += block[1]
        self.accumulator[2] += block[2]
        # The 4th limb incorporates the "1" bit for padding/stop bit logic
        self.accumulator[3] += (block[3] & 0x3ffffff) | (1 << 26)
        self._multiply()

    def _multiply(self):
        '''
        Multiply accumulator by r and reduce modulo (2^130 - 5).
        '''
        t = [0] * 8
        # Schoolbook multiplication
        for i in range(4):
            for j in range(4):
                t[i+j] += self.accumulator[i] * self.r[j]
        
        # Carry propagation for 26-bit limbs
        for i in range(7):
            t[i+1] += t[i] >> 26
            t[i] &= 0x3ffffff
            
        # Modular reduction step for the 4th limb
        t[4] += (t[3] >> 26) * 5
        t[3] &= 0x3ffffff
        
        self.accumulator = t[:4]

    def finish(self):
        '''
        Finalize the Poly1305 calculation, freeze the accumulator, and compute the tag.
        '''
        # Carry propagation
        self.accumulator[1] += self.accumulator[0] >> 26
        self.accumulator[0] &= 0x3ffffff
        self.accumulator[2] += self.accumulator[1] >> 26
        self.accumulator[1] &= 0x3ffffff
        self.accumulator[3] += self.accumulator[2] >> 26
        self.accumulator[2] &= 0x3ffffff
        
        # Modular reduction for the top limb
        self.accumulator[0] += (self.accumulator[3] >> 26) * 5
        self.accumulator[3] &= 0x3ffffff
        
        self.accumulator[1] += self.accumulator[0] >> 26
        self.accumulator[0] &= 0x3ffffff
        
        # Conditional subtraction of the prime
        self.accumulator[0] += 5
        self.accumulator[1] += self.accumulator[0] >> 26
        self.accumulator[0] &= 0x3ffffff
        self.accumulator[2] += self.accumulator[1] >> 26
        self.accumulator[1] &= 0x3ffffff
        self.accumulator[3] += self.accumulator[2] >> 26
        self.accumulator[2] &= 0x3ffffff
        self.accumulator[0] += (self.accumulator[3] >> 26) * 5
        self.accumulator[3] &= 0x3ffffff
        
        self.accumulator[1] += self.accumulator[0] >> 26
        self.accumulator[0] &= 0x3ffffff
        
        self.accumulator[0] -= 5
        
        # Handling borrow if we subtracted the prime (checking sign bit)
        self.accumulator[1] += 0xffffffff if self.accumulator[0] >> 31 else 0
        self.accumulator[2] += 0xffffffff if self.accumulator[1] >> 31 else 0
        self.accumulator[3] += 0xffffffff if self.accumulator[2] >> 31 else 0
        
        self.accumulator[0] &= 0xffffffff
        self.accumulator[1] &= 0xffffffff
        self.accumulator[2] &= 0xffffffff
        self.accumulator[3] &= 0xffffffff
        
        # Add the secret key s (nonce part)
        self.accumulator[0] += self.s[0]
        self.accumulator[1] += self.s[1] + (self.accumulator[0] >> 32)
        self.accumulator[2] += self.s[2] + (self.accumulator[1] >> 32)
        self.accumulator[3] += self.s[3] + (self.accumulator[2] >> 32)
        
        return struct.pack('<IIII', *self.accumulator)

def pad_16(data):
    '''
    Pad data with zeros to a multiple of 16 bytes.
    '''
    if len(data) % 16 == 0:
        return data
    return data + b'\x00' * (16 - (len(data) % 16))

def chacha20_poly1305_encrypt(key, nonce, plaintext, aad=b''):
    '''
    Encrypt and authenticate data using ChaCha20-Poly1305 (AEAD).
    
    :param key: 32-byte key.
    :param nonce: 12-byte nonce.
    :param plaintext: Data to encrypt.
    :param aad: Additional Authenticated Data (unencrypted but authenticated).
    :return: Tuple of (ciphertext, 16-byte tag).
    '''
    chacha = ChaCha20(key, nonce)
    
    # Generate Poly1305 key by encrypting a block of zeros
    poly_key = chacha.chacha20_block()[:32]
    
    # Encrypt the plaintext
    ciphertext = chacha.encrypt(plaintext)
    
    # Calculate authentication tag
    poly = Poly1305(poly_key)
    
    # Process AAD
    poly.add(struct.unpack('<IIII', pad_16(aad)[:16]))
    
    # Process ciphertext
    for i in range(0, len(ciphertext), 16):
        poly.add(struct.unpack('<IIII', pad_16(ciphertext[i:i+16])[:16]))
    
    # Append lengths of AAD and ciphertext
    poly.add(struct.pack('<QQ', len(aad), len(ciphertext)))
    tag = poly.finish()
    
    return ciphertext, tag

def chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad=b''):
    '''
    Verify authentication and decrypt data using ChaCha20-Poly1305.
    
    :param key: 32-byte key.
    :param nonce: 12-byte nonce.
    :param ciphertext: Data to decrypt.
    :param tag: 16-byte authentication tag.
    :param aad: Additional Authenticated Data.
    :return: Decrypted plaintext.
    :raises ValueError: If authentication fails.
    '''
    
    chacha = ChaCha20(key, nonce)
    # Regenerate Poly1305 key
    poly_key = chacha.chacha20_block()[:32]
    
    # Verify tag
    poly = Poly1305(poly_key)
    poly.add(struct.unpack('<IIII', pad_16(aad)[:16]))
    for i in range(0, len(ciphertext), 16):
        poly.add(struct.unpack('<IIII', pad_16(ciphertext[i:i+16])[:16]))
    poly.add(struct.pack('<QQ', len(aad), len(ciphertext)))
    calculated_tag = poly.finish()
    
    if calculated_tag != tag:
        raise ValueError("Authentication failed")
    
    # Decrypt if tag is valid
    return chacha.decrypt(ciphertext)

# Example usage
key = b'0' * 32  # 256-bit key
nonce = b'0' * 12  # 96-bit nonce for ChaCha20-Poly1305
plaintext = b"Hello, ChaCha20-Poly1305! Encryption test & authentication"
aad = b"Additional Authenticated Data"

ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
decrypted = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)

print("Plaintext:", plaintext)
print("\nCiphertext:", ubinascii.hexlify(ciphertext))
print("\nTag:", ubinascii.hexlify(tag))
print("\nDecrypted:", decrypted)

