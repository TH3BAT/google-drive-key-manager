# Google Drive Key Manager

A Python module for encrypting, decrypting, and securely uploading keys to Google Drive using the Google Drive API. This tool enhances security by encrypting keys with AES-256 and offers a user-friendly interface for managing sensitive information.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Functions](#functions)
- [Contributing](#contributing)
- [License](#license)

## Features
- Encrypt and decrypt keys using AES-256 encryption.
- Store keys securely in a combined file with restricted permissions.
- Upload encrypted keys to Google Drive with progress tracking.
- Download encrypted keys from Google Drive.
- Convert hexadecimal values to a combined key format.

## Requirements
- Python 3.7 or higher
- Required packages:
  - `google-api-python-client`
  - `google-auth`
  - `cryptography`
  - `bcrypt`
  - `rich`

You can install the required packages using pip:

```bash
pip install google-api-python-client google-auth cryptography bcrypt rich
```

## Installation
1. Clone this repository:

   ```bash
   git clone https://github.com/yourusername/google-drive-key-manager.git
   cd google-drive-key-manager
   ```

2. Create a Google Cloud project and enable the Google Drive API.
3. Download your service account credentials as a JSON file and save it as `client_secrets.json` in the project directory.

## Usage
1. Run the module:

   ```bash
   python your_module.py
   ```

2. Follow the prompts to:
   - Encrypt a new key
   - Decrypt an existing key
   - Convert hexadecimal values to a combined key format

### Example Usage
- To encrypt a key:
   - Choose the option to encrypt a key.
   - Enter your private key and a secure password.
   - The combined key file will be created and uploaded to your specified Google Drive folder.

- To decrypt a key:
   - Choose the option to decrypt a key.
   - Provide the Google Drive file ID of the encrypted key.
   - Enter the password to decrypt and retrieve your original key.

- To convert hexadecimal values to a combined key:
   - Choose the option to convert hex values.
   - Input the required hexadecimal values for AES key, nonce, tag, and salt.

## Functions
### `authenticate_drive()`
Authenticates and builds the Google Drive API service.

### `derive_key(password: str, salt: bytes) -> bytes`
Derives a secure key from a given password using bcrypt.

### `create_combined_key_file(file_name: str, combined_key: bytes)`
Creates a combined key file with secure permissions.

### `encrypt_key(key: str, password: str) -> bytes`
Encrypts a provided key using AES-256 encryption.

### `decrypt_key(combined_key: bytes, password: str) -> str`
Decrypts an encrypted key.

### `convert_hex_to_combined_key(hex_aes_key: str, hex_nonce: str, hex_tag: str, hex_salt: str) -> bytes`
Converts hexadecimal values into a combined key format.

### `upload_to_drive(file_name: str, content: bytes, folder_id: str = None)`
Uploads a file to Google Drive with progress tracking.

### `download_from_drive(file_id: str, file_name: str)`
Downloads a file from Google Drive.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

```

### Customization
- Replace `your_module.py` with the actual filename of your Python module.
- Update the GitHub URL in the clone command to point to your repository.
- Adjust the license section according to your project’s licensing terms.

This README provides clear instructions for users to understand the module's capabilities and how to use it effectively. If you need any further modifications or additional sections, feel free to ask!