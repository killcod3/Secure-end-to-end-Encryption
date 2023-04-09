import encryption_utils_ecc

# Generate key pair for sender and recipient
sender_private_key, sender_public_key = encryption_utils_ecc.generate_key_pair()
recipient_private_key, recipient_public_key = encryption_utils_ecc.generate_key_pair()

# Encrypt data with the recipient's public key
data = "Sensitive banking information"
encrypted_data = encryption_utils_ecc.encrypt_data(data, recipient_public_key, sender_private_key)

# Send encrypted data over the network (simulate with a variable)
received_encrypted_data = encrypted_data

# Decrypt data with the recipient's private key
decrypted_data = encryption_utils_ecc.decrypt_data(received_encrypted_data, sender_public_key, recipient_private_key)

print("Original data:", data)
print("Encrypted data:", encrypted_data)
print("Decrypted data:", decrypted_data)
