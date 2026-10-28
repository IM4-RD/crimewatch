"""
CrimeWatch — End-to-End Encryption
===================================
Flow:
  CLIENT                          SERVER
  ------                          ------
  1. Generate AES-256 key         
  2. Encrypt report with AES-GCM  
  3. Wrap AES key with server RSA public key (OAEP)
  4. Send: ciphertext + IV + tag + wrapped_key
                                  5. Unwrap AES key with RSA private key
                                  6. Decrypt only when authorized officer requests
"""

from typing import Any
# pyrefly: ignore [missing-import]
from cryptography.hazmat.primitives.asymmetric import rsa, padding
# pyrefly: ignore [missing-import]
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
# pyrefly: ignore [missing-import]
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# pyrefly: ignore [missing-import]
from cryptography.hazmat.primitives import serialization, hashes
# pyrefly: ignore [missing-import]
from cryptography.hazmat.backends import default_backend
# pyrefly: ignore [missing-import]
from cryptography.exceptions import InvalidTag
import base64, os, json

def generate_rsa_keypair(bits: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate RSA key pair for server key exchange."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def save_keypair(private_key: RSAPrivateKey, private_path: str, public_path: str):
    os.makedirs(os.path.dirname(private_path), exist_ok=True)
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open(public_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(path: str) -> RSAPrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str) -> RSAPublicKey:
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def get_public_key_pem(path: str) -> str:
    with open(path, "rb") as f:
        return f.read().decode()

# ── SERVER-SIDE: unwrap + decrypt ────────────────────────────
def server_decrypt(
    encrypted_payload: str,
    encryption_iv: str,
    encryption_tag: str,
    wrapped_key: str,
    private_key: RSAPrivateKey
) -> dict[str, Any]:
    """
    Decrypt a report payload using the server RSA private key.
    Only called when an authorized officer explicitly requests plaintext.
    """
    # 1. Unwrap AES key
    aes_key = private_key.decrypt(
        base64.b64decode(wrapped_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # 2. Decrypt payload
    aesgcm = AESGCM(aes_key)
    iv = base64.b64decode(encryption_iv)
    ciphertext_and_tag = base64.b64decode(encrypted_payload) + base64.b64decode(encryption_tag)
    plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, None)
    return json.loads(plaintext.decode("utf-8"))

# ── CLIENT-SIDE EQUIVALENT (Python, for testing) ─────────────
def client_encrypt(payload: dict[str, Any], public_key: RSAPublicKey) -> dict[str, str]:
    """
    Encrypt a report payload with a fresh AES-256 key,
    then wrap the AES key with the server RSA public key.
    In production this runs in the browser via WebCrypto API.
    """
    aes_key = os.urandom(32)  # 256-bit
    iv      = os.urandom(12)  # 96-bit GCM IV
    aesgcm  = AESGCM(aes_key)
    plaintext = json.dumps(payload).encode("utf-8")
    encrypted = aesgcm.encrypt(iv, plaintext, None)  # last 16 bytes = tag
    ciphertext = encrypted[:-16]
    tag        = encrypted[-16:]
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {
        "encrypted_payload": base64.b64encode(ciphertext).decode(),
        "encryption_iv":     base64.b64encode(iv).decode(),
        "encryption_tag":    base64.b64encode(tag).decode(),
        "wrapped_key":       base64.b64encode(wrapped_key).decode(),
    }
