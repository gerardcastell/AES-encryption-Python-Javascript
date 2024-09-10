#!/usr/bin/env python3

import json
import base64
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# AES block size for CBC mode
BLOCK_SIZE = 16

def pad_key(key):
    """Ensure the key is exactly 32 bytes (AES-256 requires this)."""
    key_bytes = key.encode('utf-8')
    if len(key_bytes) > 32:
        return key_bytes[:32]  # Trim if the key is too long
    elif len(key_bytes) < 32:
        return key_bytes.ljust(32, b'\0')  # Pad with null bytes if too short
    return key_bytes

def encrypt_aes(data, key):
    # Prepare the key and the IV
    print("key: ", key)
    key = pad_key(key)  # Ensure the key is 32 bytes for AES-256
    iv = get_random_bytes(BLOCK_SIZE)  # Generate a random IV (16 bytes)
    iv_string = base64.b64encode(iv).decode('utf-8')
    print("iv: ", iv_string)
    # Create a cipher object with the key and the IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Convert the JSON data to bytes and apply PKCS7 padding
    data_bytes = json.dumps(data).encode('utf-8')
    padded_data = pad(data_bytes, BLOCK_SIZE)

    # Encrypt the padded data
    encrypted_data = cipher.encrypt(padded_data)

    # Return the base64 encoded IV concatenated with the encrypted data
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt_aes(data, key):
    # Prepare the key
    key = pad_key(key)  # Ensure the key is 32 bytes for AES-256

    # Decode the base64 data
    data = base64.b64decode(data.encode('utf-8'))

    # Extract the IV and the encrypted data
    iv = data[:BLOCK_SIZE]
    encrypted_data = data[BLOCK_SIZE:]

    # Create a cipher object with the key and the IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the data and remove the padding
    decrypted_data = cipher.decrypt(encrypted_data)
    unpadded_data = decrypted_data.rstrip(b'\0')
    decrypted_data = unpadded_data.decode('utf-8')
    # Return the JSON data as a dictionary
    return decrypted_data

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./encrypt.py <input_json_file> <encryption_key>")
        sys.exit(1)

    input_file = sys.argv[1]
    key = sys.argv[2]

    try:
        # Read the JSON data from the input file
        with open(input_file, 'r') as f:
            json_data = json.load(f)

        # Encrypt the data using AES-256 with CBC mode
        encrypted_data = encrypt_aes(json_data, key)

        # Write the encrypted data to 'encrypted-input.txt'
        with open('encrypted-input.txt', 'w') as encrypted_file:
            encrypted_file.write(encrypted_data)

        print("Encrypted data written to 'encrypted-input.txt'.")
        decrypt_aes(encrypted_data, key)
        print("Decrypted data: ", decrypt_aes(encrypted_data, key))

    except Exception as e:
        print("Error:", str(e))
