import encryption_utils_rsa

# Generate key pair for sender and recipient
sender_private_key, sender_public_key = encryption_utils.generate_key_pair()
recipient_private_key, recipient_public_key = encryption_utils.generate_key_pair()

# Encrypt data with the recipient's public key
data = "Sensitive information"
encrypted_data = encryption_utils.encrypt_data(data, recipient_public_key)

# Send encrypted data over the network (simulate with a variable)
received_encrypted_data = encrypted_data

# Decrypt data with the recipient's private key
decrypted_data = encryption_utils.decrypt_data(received_encrypted_data, recipient_private_key)

print("Original data:", data)
print("Encrypted data:", encrypted_data)
print("Decrypted data:", decrypted_data)
