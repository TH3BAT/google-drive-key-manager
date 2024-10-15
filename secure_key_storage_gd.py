"""
This module provides a secure framework for encrypting and decrypting sensitive data, specifically private keys, using AES-256 encryption. It integrates with the Google Drive API for seamless storage and retrieval of encrypted files.

 Key Features:
   - **Key Derivation**: Utilizes bcrypt with a unique salt for deriving a secure encryption key from a user-provided password, providing strong protection against 
     brute-force and rainbow table attacks.

   - **Encryption**: Supports AES-256 encryption in GCM mode, ensuring both confidentiality and integrity of the encrypted data. Encryption components (salt, nonce, 
     tag, and ciphertext) are combined into a single file for simplified management.

   - **File Handling and Permissions**: Automatically manages the creation of a combined key file (including salt, nonce, tag, and encrypted data) and saves it with 
     secure `600` permissions (read/write for the owner only).

   - **Google Drive Integration**: Allows for secure uploading and downloading of encrypted files to and from Google Drive, enabling easy access to stored sensitive 
     data while keeping it encrypted.

   - **Hex Conversion Support**: Provides an option for converting individual AES keys, nonces, tags, and salts from hexadecimal values into a single combined key format 
     for easy handling.

   - **User Input Management**: Utilizes secure password prompts to prevent exposure of sensitive information during key encryption and decryption processes. The user can 
     convert existing encryption parameters into the new format or decrypt using the combined key.

 Usage:
  1. Run the module and choose one of the following:
     - (e)ncrypt a new key: Input your private key and a password to generate an encrypted file stored securely with `600` permissions and uploaded to Google Drive.
     - (d)ecrypt an existing key: Download the encrypted file from Google Drive and input the password to retrieve your private key.
     - (c)onvert hex to combined key: Input existing AES key, nonce, tag, and salt in hexadecimal format to generate a new combined key file.

 Dependencies:
  - Requires the `cryptography` library for cryptographic operations.
  - Requires the `google-api-python-client` library for Google Drive API interactions.
  
 Note: Ensure you have a valid Google service account with appropriate permissions and the `client_secrets.json` file for Google Drive authentication.
"""


import os
import stat
import json
import base64
import getpass
import secrets
import bcrypt
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Constants for Google Drive API
SCOPES = ['https://www.googleapis.com/auth/drive.file']
SERVICE_ACCOUNT_FILE = 'client_secrets.json'

def authenticate_drive():
    creds = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    drive_service = build('drive', 'v3', credentials=creds)
    return drive_service

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from a password using bcrypt."""
    # Use bcrypt to hash the password with the provided salt
    return bcrypt.kdf(password.encode(), salt, desired_key_bytes=32, rounds=100000)

def create_combined_key_file(file_name: str, combined_key: bytes):
    """Write the combined key to a file with 600 permissions."""
    with open(file_name, 'wb') as f:
        f.write(combined_key)
    
    # Set file permissions to 600 (read/write for owner only)
    os.chmod(file_name, stat.S_IRUSR | stat.S_IWUSR)

def encrypt_key(key: str, password: str) -> bytes:
    """Encrypt the key using AES-256 encryption and combine all components into one file."""
    
    # Generate salt and derive AES key from password and salt
    salt = bcrypt.gensalt()
    encryption_key = derive_key(password, salt)

    # Generate nonce
    nonce = os.urandom(16)

    # Create AES cipher
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad and encrypt the key
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(key.encode()) + padder.finalize()
    encrypted_key = encryptor.update(padded_data) + encryptor.finalize()
    tag = encryptor.tag

    # Combine all components (AES key, nonce, tag, and salt)
    combined_key = salt + nonce + tag + encrypted_key
    return combined_key

def decrypt_key(combined_key: bytes, password: str) -> str:
    """Decrypt the key using AES-256 from the combined key file."""
    
    # Extract the components from the combined key
    salt = combined_key[:29]  # bcrypt salt is 29 bytes
    nonce = combined_key[29:45]  # nonce is 16 bytes
    tag = combined_key[45:61]  # tag is 16 bytes
    encrypted_key = combined_key[61:]  # the rest is the encrypted key

    # Derive AES key from password and salt
    encryption_key = derive_key(password, salt)

    # Create AES cipher for decryption
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and unpad the key
    padded_data = decryptor.update(encrypted_key) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_key = unpadder.update(padded_data) + unpadder.finalize()

    return decrypted_key.decode()

def convert_hex_to_combined_key(hex_aes_key: str, hex_nonce: str, hex_tag: str, hex_salt: str) -> bytes:
    """Convert individual hex values back into a single combined key format."""
    salt = bytes.fromhex(hex_salt)
    nonce = bytes.fromhex(hex_nonce)
    tag = bytes.fromhex(hex_tag)
    aes_key = bytes.fromhex(hex_aes_key)
    
    return salt + nonce + tag + aes_key

def upload_to_drive(file_name: str, content: bytes, folder_id: str = None):
    drive_service = authenticate_drive()

    # Set the file metadata
    file_metadata = {'name': file_name}
    
    # If a folder ID is provided, add it to the file metadata
    if folder_id:
        file_metadata['parents'] = [folder_id]

    # Write content to file
    with open(file_name, 'wb') as file:
        file.write(content)

    # Create a MediaFileUpload object
    media = MediaFileUpload(file_name, mimetype='text/plain')

    # Create and execute the file upload request
    uploaded_file = drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()

    # Print the file ID of the uploaded file
    print(f"File uploaded successfully to folder ID {folder_id}. File ID: {uploaded_file['id']}")

def download_from_drive(file_id: str, file_name: str):
    drive_service = authenticate_drive()
    request = drive_service.files().get_media(fileId=file_id)
    
    with open(file_name, 'wb') as file:
        downloader = MediaIoBaseDownload(file, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            print(f"Download {int(status.progress() * 100)}% complete.")

def main():
    combined_key_file = 'combined.key'

    action = input("Do you want to (e)ncrypt a new key, (d)ecrypt an existing one, or (c)onvert hex to combined key? (e/d/c): ").lower()

    if action == 'e':
        private_key = input("Enter your private key to encrypt: ")
        password = getpass.getpass("Enter a password to secure the key: ")
        combined_key = encrypt_key(private_key, password)
        
        # Save the combined key to file with 600 permissions
        create_combined_key_file(combined_key_file, combined_key)

        print(f"Combined key saved to {combined_key_file} with secure permissions.")
        
        # Upload to Google Drive
        folder_id = 'google_drive_folder_id'  # Specify your Google Drive folder ID
        upload_to_drive(combined_key_file, combined_key, folder_id)
        print("Encrypted key uploaded to Google Drive.")

    elif action == 'd':
        file_id = input("Enter the Google Drive file ID to download: ")
        download_from_drive(file_id, combined_key_file)

        # Read the downloaded combined key
        with open(combined_key_file, 'rb') as file:
            combined_key = file.read()

        # Decrypt the key
        password = getpass.getpass("Enter the password to decrypt the key: ")
        decrypted_key = decrypt_key(combined_key, password)
        print(f"Decrypted Key: {decrypted_key}")

    elif action == 'c':
        hex_aes_key = input("Enter AES key (in hexadecimal): ")
        hex_nonce = input("Enter nonce (in hexadecimal): ")
        hex_tag = input("Enter tag (in hexadecimal): ")
        hex_salt = input("Enter salt (in hexadecimal): ")

        # Convert individual hex values into combined key
        combined_key = convert_hex_to_combined_key(hex_aes_key, hex_nonce, hex_tag, hex_salt)
        
        # Save the combined key to file with 600 permissions
        create_combined_key_file(combined_key_file, combined_key)
        print(f"Converted hex values saved to {combined_key_file}.")

if __name__ == '__main__':
    main()
