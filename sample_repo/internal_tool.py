from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_cache_entry(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()
