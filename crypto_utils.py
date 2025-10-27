# crypto_utils.py
from cryptography.fernet import Fernet

# Generate a key (run this once and share between clients if needed)
key = Fernet.generate_key()
print(key)

# For now, we use a fixed key for simplicity (same key on all clients)
key = b'FgF8nP5Z5uZkKmcBf2WcpE4G2hrK2Z2m_wIE5rI2BvA='  
cipher = Fernet(key)

def encrypt_message(message: str) -> bytes:
    """Encrypts a plain text message."""
    return cipher.encrypt(message.encode())

def decrypt_message(token: bytes) -> str:
    """Decrypts a message token back to plain text."""
    return cipher.decrypt(token).decode()
