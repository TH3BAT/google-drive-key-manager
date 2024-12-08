# Google Key Drive Manager

## Overview

This module provides a secure framework for encrypting and decrypting sensitive data, specifically private keys, using AES-256 encryption. It integrates with the Google Drive API for seamless storage and retrieval of encrypted files.

## Key Features

- **Key Derivation**: Utilizes bcrypt with a unique salt to derive a secure encryption key from a user-provided password, providing strong protection against brute-force and rainbow table attacks.
  
- **Encryption**: Supports AES-256 encryption in GCM mode, ensuring both confidentiality and integrity of the encrypted data. Encryption components (salt, nonce, tag, and ciphertext) are combined into a single file for simplified management.
  
- **File Handling and Permissions**: Automatically manages the creation of a combined key file (including salt, nonce, tag, and encrypted data) and saves it with secure 600 permissions (read/write for the owner only).
  
- **Google Drive Integration**: Allows for secure uploading and downloading of encrypted files to and from Google Drive, enabling easy access to stored sensitive data while keeping it encrypted.
  
- **Hex Conversion Support**: Provides an option to enter individual AES components (key, nonce, tag, and salt) in hexadecimal format if the combined key file is lost. This feature allows users to recreate the combined key directly, adding a secondary recovery method.
  
- **User Input Management**: Utilizes secure password prompts to prevent exposure of sensitive information during key encryption and decryption processes. The user can either convert existing encryption parameters into the new format or decrypt using the combined key.

## Usage

1. Run the module and choose one of the following:
    - **(e)ncrypt a new key**: Input your private key and a password to generate an encrypted file stored securely with 600 permissions and uploaded to Google Drive.
    - **(d)ecrypt an existing key**: Download the encrypted file from Google Drive or manually input hex values if the file is missing, then enter the password to retrieve your private key.
    - **(c)onvert hex to combined key**: Input existing AES key, nonce, tag, and salt in hexadecimal format to generate a new combined key file for backup.

## Dependencies

- Requires the `cryptography` library for cryptographic operations.
- Requires the `google-api-python-client` library for Google Drive API interactions.
  
**Note**: Ensure you have a valid Google service account with appropriate permissions and the `client_secrets.json` file for Google Drive authentication.

## Authentication and Setup

To authenticate with the Google Drive API, you need a valid service account file. Ensure that your `client_secrets.json` file is available and contains the necessary credentials for Google Drive integration.

## Example Workflow

1. **Encrypt a new key**:
   - Input your private key and a password to generate a new encrypted file.
   - The file will be saved with secure 600 permissions and uploaded to Google Drive.

2. **Decrypt an existing key**:
   - Download the encrypted file from Google Drive or manually input the hex values if the file is lost.
   - Enter your password to decrypt the key.

3. **Convert hex to combined key**:
   - If you have individual AES components (key, nonce, tag, salt) in hexadecimal format, you can use this option to generate a combined key file for backup.

## Code Example

```python
# Code snippets for encryption and decryption are provided in the script above.
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributions

Contributions are welcome! Feel free to open an issue or submit a pull request.
