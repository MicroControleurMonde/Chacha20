# RFC 7539 implementation (partial) - ChaCha20
# For educationnal purposes only


import struct

def rotl32(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

class ChaCha20:
    def __init__(self, key, nonce):
        self.input = [0] * 16
        self.input[0] = 0x61707865
        self.input[1] = 0x3320646e
        self.input[2] = 0x79622d32
        self.input[3] = 0x6b206574
        
        # Charger la clé
        key_ints = struct.unpack('<8I', key)
        self.input[4:12] = key_ints
        
        # Charger le nonce
        self.input[12] = 0
        self.input[13] = 0
        nonce_ints = struct.unpack('<2I', nonce)
        self.input[14:16] = nonce_ints

    def quarter_round(self, x, a, b, c, d):
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
        x = self.input.copy()
        for _ in range(10):
            self.quarter_round(x, 0, 4, 8, 12)
            self.quarter_round(x, 1, 5, 9, 13)
            self.quarter_round(x, 2, 6, 10, 14)
            self.quarter_round(x, 3, 7, 11, 15)
            self.quarter_round(x, 0, 5, 10, 15)
            self.quarter_round(x, 1, 6, 11, 12)
            self.quarter_round(x, 2, 7, 8, 13)
            self.quarter_round(x, 3, 4, 9, 14)
        
        output = []
        for i in range(16):
            output.append((x[i] + self.input[i]) & 0xffffffff)
        
        self.input[12] = (self.input[12] + 1) & 0xffffffff
        if self.input[12] == 0:
            self.input[13] = (self.input[13] + 1) & 0xffffffff
        
        return struct.pack('<16I', *output)

    def encrypt(self, plaintext):
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 64):
            block = self.chacha20_block()
            for j in range(min(64, len(plaintext) - i)):
                ciphertext.append(plaintext[i+j] ^ block[j])
        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)  # ChaCha20 est symétrique

# Exemple d'utilisation
key = b'0' * 32  # Clé de 256 bits
nonce = b'0' * 8  # Nonce de 64 bits

chacha = ChaCha20(key, nonce)
plaintext = b"Hello, ChaCha20! Essai de chiffrage & dechiffrage"
ciphertext = chacha.encrypt(plaintext)
chacha = ChaCha20(key, nonce)  # Réinitialiser l'état pour le déchiffrement
decrypted = chacha.decrypt(ciphertext)

print("Plaintext:", plaintext)
print("\nCiphertext:", ciphertext)
print("\nDecrypted:", decrypted)

