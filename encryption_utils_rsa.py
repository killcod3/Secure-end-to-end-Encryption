from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

KEY_SIZE = 2048
BLOCK_SIZE = 128

def generate_key_pair():
    key = RSA.generate(KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_data(data, public_key):
    recipient_key = RSA.import_key(public_key)
    session_key = get_random_bytes(BLOCK_SIZE)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(data.encode('utf-8'), BLOCK_SIZE))
    return b64encode(enc_session_key + cipher_aes.iv + ciphertext).decode('utf-8')

def decrypt_data(data, private_key):
    key = RSA.import_key(private_key)

    data = b64decode(data)
    enc_session_key, iv, ciphertext = data[:KEY_SIZE // 8], data[KEY_SIZE // 8:KEY_SIZE // 8 + 16], data[KEY_SIZE // 8 + 16:]
    
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    return unpad(cipher_aes.decrypt(ciphertext), BLOCK_SIZE).decode('utf-8')
