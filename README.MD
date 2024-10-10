# Secure Key Encryption and Decryption Module

This module provides a robust framework for encrypting and decrypting sensitive data, particularly private keys, using AES-256 encryption. It seamlessly integrates with the Google Drive API for efficient storage and retrieval of encrypted files.

## Key Features

- **Key Derivation**:  
  Utilizes `bcrypt` with a unique salt to derive a secure encryption key from a user-provided password, offering strong protection against brute-force and rainbow table attacks.

- **Encryption**:  
  Supports AES-256 encryption in GCM mode, ensuring both confidentiality and integrity of the encrypted data.

- **File Handling**:  
  Automatically manages the generation and storage of required key files (salt, nonce, tag) during encryption. If these files are missing during decryption, the module prompts the user for manual input.

- **Google Drive Integration**:  
  Securely uploads and downloads encrypted files to and from Google Drive, allowing easy access to stored sensitive data.

- **User Input Management**:  
  Uses secure password prompts to prevent the exposure of sensitive information during the key encryption and decryption processes.

## Usage

1. **Run the module**: Choose to either encrypt a new key or decrypt an existing one.
2. **Encryption**:  
   - Input your private key and a password to generate an encrypted file.  
   - The encrypted file will be stored in Google Drive.
3. **Decryption**:  
   - Download the encrypted file from Google Drive.  
   - Input the password to retrieve your private key.

## Dependencies

- Requires the `cryptography` library for cryptographic operations.
- Requires the `google-api-python-client` library for Google Drive API interactions.

## Note

Ensure that you have:
- A valid Google service account with appropriate permissions.
- The `client_secrets.json` file for authentication.
