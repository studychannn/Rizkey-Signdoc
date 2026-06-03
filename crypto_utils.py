import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key



def encrypt_private_key(private_key, passphrase: str) -> str:
    """Encrypt private key with user passphrase using AES-256."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad to block size
    pad_len = 16 - (len(pem) % 16)
    pem_padded = pem + bytes([pad_len] * pad_len)
    encrypted = encryptor.update(pem_padded) + encryptor.finalize()
    result = salt + iv + encrypted
    return base64.b64encode(result).decode()


def decrypt_private_key(encrypted_b64: str, passphrase: str):
    """Decrypt private key with user passphrase."""
    data = base64.b64decode(encrypted_b64)
    salt = data[:16]
    iv = data[16:32]
    encrypted = data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    pem_padded = decryptor.update(encrypted) + decryptor.finalize()
    pad_len = pem_padded[-1]
    pem = pem_padded[:-pad_len]
    private_key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    return private_key


def get_public_key_pem(private_key) -> str:
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def hash_file(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def sign_document(private_key, doc_hash: str) -> str:
    """Sign document hash dengan RSA-2048-PSS, returns base64 signature."""
    message = doc_hash.encode()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(public_key_pem: str, doc_hash: str, signature_b64: str) -> bool:
    """Verify RSA-2048-PSS signature against document hash."""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )
        signature = base64.b64decode(signature_b64)
        message = doc_hash.encode()
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
