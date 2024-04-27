import os
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Load the encryption and HMAC keys from environment variables
KEY = os.environ.get("ENCRYPTION_KEY").encode()  # This key should be securely generated and stored
HMAC_KEY = os.environ.get("HMAC_KEY").encode()   # Ensure this key is also securely generated and stored

def encrypt_message(message: str) -> Tuple[str, str]:
    """
    Encrypts a message using Fernet symmetric encryption and returns the encrypted message and its HMAC.
    """
    f = Fernet(KEY)
    if isinstance(message, str):
        message = message.encode()
    encrypted_message = f.encrypt(message)

    # Generate HMAC
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_message)
    hmac_value = h.finalize()

    return encrypted_message.decode(), hmac_value.hex()

def decrypt_message(encrypted_message: str, received_hmac: str) -> str:
    """
    Decrypts an encrypted message using Fernet symmetric encryption and verifies HMAC.
    """
    # Verify HMAC first
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_message.encode())
    try:
        h.verify(bytes.fromhex(received_hmac))
        f = Fernet(KEY)
        decrypted_message = f.decrypt(encrypted_message.encode())
        return decrypted_message.decode()
    except Exception as e:
        raise ValueError("HMAC verification failed") from e




import base64
