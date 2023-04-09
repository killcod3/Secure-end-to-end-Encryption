# Secure-end-to-end-Encryption

This repository provides two examples of end-to-end encryption systems for a banking API using Python. The first example uses RSA for key exchange and AES for data encryption, while the second example uses Elliptic Curve Cryptography (ECC) for key exchange and AES for data encryption. These examples are for educational purposes and should not be used in a production environment without thorough review, testing, and adaptation to your specific use case.

## Installation

To install the required dependencies, run the following command:

```
pip install pycryptodome cryptography
```

## Usage

### RSA for Key Exchange and AES for Data Encryption

1. Import the `encryption_utils_rsa` module in your application:

```python
import encryption_utils
```

2. Use the functions provided in `encryption_utils_rsa` to perform end-to-end encryption:

```python
# Generate key pair for sender and recipient
sender_private_key, sender_public_key = encryption_utils.generate_key_pair()
recipient_private_key, recipient_public_key = encryption_utils.generate_key_pair()

# Encrypt data with the recipient's public key
data = "Sensitive banking information"
encrypted_data = encryption_utils.encrypt_data(data, recipient_public_key)

# Send encrypted data over the network (simulate with a variable)
received_encrypted_data = encrypted_data

# Decrypt data with the recipient's private key
decrypted_data = encryption_utils.decrypt_data(received_encrypted_data, recipient_private_key)
```

### ECC for Key Exchange and AES for Data Encryption

1. Import the `encryption_utils_ecc` module in your application:

```python
import encryption_utils_ecc
```

2. Use the functions provided in `encryption_utils_ecc` to perform end-to-end encryption:

```python
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
```

## Disclaimer

These examples are for educational purposes only and should not be used in a production environment without thorough review, testing, and adaptation to your specific use case. Always consult with security experts and follow industry best practices to ensure the safety of sensitive financial data.
