import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_transaction_record(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def record_checksum(record_bytes: bytes) -> str:
    return hashlib.sha1(record_bytes).hexdigest()
