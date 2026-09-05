from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class DocumentSigner:
    def __init__(self):
     self.signing_key = rsa.generate_private_key(public_exponent=65537,key_size=4096,)
    def sign_document(self, document: bytes) -> bytes:
        return self.signing_key.sign(document,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

    def get_key(self):
     return self.signing_key
