from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
def generate_signing_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key

def sign_auth_token(private_key, token_bytes: bytes) -> bytes:
    signature = private_key.sign(token_bytes,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256(),)
    return signature

def generate_ecdh_key():
    return ec.generate_private_key(ec.SECP384R1())

def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(),peer_public_key)