# Chacha20 / ChaCha20-Poly1305 (Crypto implementations)


[![Security: ChaCha20](https://img.shields.io/badge/Security-Chacha20--Poly1305-blue)](https://tools.ietf.org/html/rfc7539)

---

## Index

1. [Context](#context)
2. [Why](#Why) 
3. [Project description](#project-description)
4. [Prerequisites](#prerequisites)
5. [Use](#use)
6. [Example of output](#example-of-output)
7. [Operation](#operation)
8. [Acknowledgment](#acknowledgment)
9. [Disclaimer](#disclaimer)

---

## Context

This repository contains two standalone MicroPython modules implementing cryptographic standards.

These implementations are designed for resource-constrained environments where MicroPython is used (such as ESP32, RP2040, or similar microcontrollers).

The provided modules are:

- **Chacha20.v0.py**: A lightweight implementation of the ChaCha20 stream cipher.
  
- **Chacha20_Poly1305.v0.py**: An implementation combining ChaCha20 and the Poly1305 authenticator to provide Authenticated Encryption with Associated Data (AEAD).
  

---

## Why

In the rapidly growing world of the Internet of Things (IoT), microcontrollers (MCUs) are increasingly required to handle sensitive data and secure communications. However, these devices often operate with limited RAM, processing power, and storage space, making it difficult or impossible to run standard, heavy cryptographic libraries (like OpenSSL) written for full-fledged Operating Systems.

**The need for lightweight code:**

1. **Resource Efficiency**: Standard cryptographic libraries are too large for the flash memory of many MCUs. These MicroPython implementations are stripped down to the essentials, fitting easily into the constrained memory budgets of devices like the ESP32 or Raspberry Pi Pico.
2. **Performance**: ChaCha20 is specifically designed to be faster than older algorithms on software platforms that lack dedicated hardware acceleration for AES. It relies on simple additions, rotations, and XORs, which are handled efficiently by microcontrollers.
3. **Flexibility**: By using MicroPython, developers gain the ability to <mark>prototype </mark>and deploy secure logic rapidly without the complexity of C/C++ memory management, while still maintaining a reasonable level of performance.
4. **Modern Security**: Unlike outdated or proprietary algorithms often found in older MCU examples, ChaCha20-Poly1305 provides a modern, high-security standard (used in protocols like TLS 1.3 and SSH) that ensures both confidentiality (encryption) and integrity (authentication) of data.

This project<mark> bridges the gap between high-end security and low-end hardware</mark>, enabling makers and engineers to encrypt communications (MQTT, Wi-Fi, LoRa) and stored data securely.

---


## Project description

### 1. Chacha20.v0.py

This module provides a MicroPython implementation of the **ChaCha20** encryption algorithm as defined in **RFC 7539**.

- **Algorithm**: ChaCha20 Stream Cipher.
- **Key Size**: 256-bit (32 bytes).
- **Nonce Size**: 64-bit (8 bytes) as per the specific implementation configuration.
- **Features**: Symmetric encryption (identical process for encryption and decryption), 32-bit bitwise operations, and block counter management.

### 2. Chacha20_Poly1305.v0.py

This module provides a MicroPython implementation of the **ChaCha20-Poly1305** AEAD construction.

- **Algorithm**: ChaCha20 (stream cipher) + Poly1305 (message authenticator).
- **Key Size**: 256-bit (32 bytes).
- **Nonce Size**: 96-bit (12 bytes).
- **Features**: Confidentiality (encryption) and Integrity (authentication).

---

## Prerequisites

- **MicroPython**: The code uses the `struct` and `ubinascii` (in the AEAD version) modules, which are standard in MicroPython firmware.
- **Hardware**: Any device capable of running MicroPython (ESP8266, ESP32, Pyboard, etc.).
- **Python Libraries**: <mark>No external third-party libraries </mark>are required.

---

## Use

### Chacha20.v0.py

```python
from Chacha20 import ChaCha20

# Initialize with a 256-bit key and a 64-bit nonce
key = b'0' * 32
nonce = b'0' * 8

cipher = ChaCha20(key, nonce)
plaintext = b"Hello, ChaCha20!"

# Encrypt
ciphertext = cipher.encrypt(plaintext)

# Decrypt (requires re-initialization to reset counter)
decipher = ChaCha20(key, nonce)
decrypted = decipher.decrypt(ciphertext)

print(f"Decrypted: {decrypted}")
```

### Chacha20_Poly1305.v0.py

```python
from Chacha20_Poly1305 import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt

# Initialize with a 256-bit key and a 96-bit nonce
key = b'0' * 32
nonce = b'0' * 12
aad = b"Additional Authenticated Data"
plaintext = b"Secret message"

# Encrypt and Authenticate
ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)

# Verify and Decrypt
try:
    decrypted = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)
    print(f"Success: {decrypted}")
except ValueError:
    print("Authentication failed!")
```

---

## Example of output

### Output for Chacha20.v0.py

```text
MPY: soft reboot
Plaintext: b'Hello, ChaCha20! Encryption & decryption test'

Ciphertext: b'\x92j\x04\x1a"\x8cG\x8f\xf8\xf8C\xe9\xfa\xac\x95\xa4:\xec\xc3\x90\xc4\t$#\xbc4\x90\x87\x11\xc5s-\x97\xee\x1ci\xc3t\xff\xbb\x83\xc7\xcb\x1d\xb5\x86\xc2\x8a.'

Decrypted: b'Hello, ChaCha20! Encryption & decryption test'
```

### Output for Chacha20_Poly1305.v0.py

```text
MPY: soft reboot
Plaintext: b'Hello, ChaCha20-Poly1305! Encryption test & authentication'

Ciphertext: b'f6efca3839895f8b5e5784a680396a683df9b5360ef9ea4989071a311f780156df8374b70142e6d6fafc0de0466c2bfbc97a95649058fc571668'

Tag: b'b84eb9e615205f4a4dd350f364456960'

Decrypted: b'Hello, ChaCha20-Poly1305! Encryption test & authentication'
```

## Operation

### Chacha20 (Chacha20.v0.py)

1. **Initialization**: The state matrix (16 words) is initialized with constants ("expa nd 3 2-by te k"), the 256-bit key, the block counter (0), and the 64-bit nonce.
2. **Block Generation**: The `chacha20_block` function creates a 64-byte keystream block. It performs 10 rounds (consisting of column and diagonal rounds) of the `quarter_round` function.
3. **Encryption**: The plaintext is XORed with the generated keystream block. The block counter increments automatically after every 64 bytes of processed data.
4. **Decryption**: The process is identical to encryption (XORing ciphertext with the same keystream).

### Chacha20-Poly1305 (Chacha20_Poly1305.v0.py)

1. **Key Generation**: The Poly1305 one-time key is generated by encrypting a 32-byte block of zeros using the ChaCha20 instance with the provided key and nonce (with block counter 0).
2. **Encryption**: The plaintext is encrypted using ChaCha20 (starting at block counter 1).
3. **Authentication**: The Poly1305 authenticator calculates a 16-byte tag over:
  - The Additional Authenticated Data (AAD), padded to 16 bytes.
  - The Ciphertext, padded to 16 bytes.
  - The lengths of the AAD and Ciphertext.
4. **Decryption**: The recipient regenerates the Poly1305 key and tag using the ciphertext and AAD. If the calculated tag matches the received tag, the ciphertext is decrypted. If not, a `ValueError` is raised.

---

## Acknowledgment

- **RFC 7539**: The implementation follows the specification defined in [RFC 7539](https://tools.ietf.org/html/rfc7539).
- **Daniel J. Bernstein**: Original designer of the ChaCha20 stream cipher and Poly1305 authenticator.
- **MicroControleurMonde**: Author of the MicroPython adaptation.

---

## Disclaimer

This code is provided **for educational purposes only**.

While it follows standard cryptographic specifications, it has not undergone rigorous security auditing or formal certification. It may not be resistant to side-channel attacks (timing, cache, etc.).

- **Do not** use this code in production systems requiring high assurance of security.
  
- **Do not** use this code to protect sensitive personal, financial, or medical data.
  
- The author assume no liability for any damages resulting from the use or misuse of this software.
  

---
