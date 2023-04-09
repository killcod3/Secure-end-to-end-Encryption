from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import b64encode, b64decode

BLOCK_SIZE = 128

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'bank-api-key',
    ).derive(shared_key)
    return derived_key

def encrypt_data(data, recipient_public_key, sender_private_key):
    shared_key = derive_shared_key(sender_private_key, recipient_public_key)
    cipher_aes = AES.new(shared_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(data.encode('utf-8'), BLOCK_SIZE))
    return b64encode(cipher_aes.iv + ciphertext).decode('utf-8')

def decrypt_data(data, sender_public_key, recipient_private_key):
    shared_key = derive_shared_key(recipient_private_key, sender_public_key)
    data = b64decode(data)
    iv, ciphertext = data[:16], data[16:]
    cipher_aes = AES.new(shared_key, AES.MODE_CBC, iv)
    return unpad(cipher_aes.decrypt(ciphertext), BLOCK_SIZE).decode('utf-8')
