"""
This module provides a secure framework for encrypting and decrypting sensitive data, specifically private keys, using AES-256 encryption. It integrates with the Google Drive API for seamless storage and retrieval of encrypted files.

 Key Features:
   - Key Derivation: Utilizes bcrypt with a unique salt for deriving a secure encryption key from a user-provided password, providing strong protection against brute-force and rainbow table attacks.

   - Encryption: Supports AES-256 encryption in GCM mode, ensuring both confidentiality and integrity of the encrypted data.

   - File Handling: Automatically manages the generation and storage of necessary key files (salt, nonce, tag) or prompts the user for manual input if these files are missing during decryption.

   - Google Drive Integration: Allows for secure uploading and downloading of encrypted files to and from Google Drive, enabling easy access to stored sensitive data.

   - User Input Management: Utilizes secure password prompts to prevent exposure of sensitive information during key encryption and decryption processes.

 Usage:
  1. Run the module and choose to either encrypt a new key or decrypt an existing one.
  2. For encryption, input your private key and a password to generate an encrypted file stored in Google Drive.
  3. For decryption, download the encrypted file from Google Drive and input the password to retrieve your private key.

 Dependencies:
  - Requires the `cryptography` library for cryptographic operations.
  - Requires the `google-api-python-client` library for Google Drive API interactions.

Note: Ensure you have a valid Google service account with appropriate permissions and the `client_secrets.json` file for authentication.
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
    return bcrypt.kdf(password.encode(), salt, desired_key_bytes=32, rounds=100)

def create_key_file(file_name: str, size: int) -> bytes:
    """Create a key file with random bytes if it doesn't exist."""
    if not os.path.exists(file_name):
        key = os.urandom(size)
        with open(file_name, 'wb') as f:
            f.write(key)
        
        # Set file permissions to 600 (read/write for owner only)
        os.chmod(file_name, stat.S_IRUSR | stat.S_IWUSR)
    else:
        with open(file_name, 'rb') as f:
            key = f.read()
    return key

def encrypt_key(key: str, password: str, aes_key: str, nonce_key: str, tag_key: str):
    """Encrypt the key using AES-256 encryption."""
    
    # Generate salt
    salt = bcrypt.gensalt()  # Generate a new salt with bcrypt
    with open('salt.key', 'wb') as sf:
        sf.write(salt)

    # Derive AES key from password and salt
    encryption_key = derive_key(password, salt)

    # Generate nonce
    nonce = os.urandom(16)  # Generate a new nonce
    with open(nonce_key, 'wb') as kf:
        kf.write(nonce)

    # Create AES cipher
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the key and encrypt
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(key.encode()) + padder.finalize()
    encrypted_key = encryptor.update(padded_data) + encryptor.finalize()  # Encrypt the padded data
    tag = encryptor.tag  # Get the tag

    # Save tag
    with open(tag_key, 'wb') as kf:
        kf.write(tag)

    return encrypted_key, nonce, tag, salt

def decrypt_key(encrypted_key: bytes, password: str, nonce_key: str, tag_key: str) -> str:
    """Decrypt the key using AES-256 encryption."""
    salt = None
    nonce = None
    tag = None
    
    # Try to read salt, nonce, and tag from files
    try:
        with open('salt.key', 'rb') as sf:
            salt = sf.read()
    except FileNotFoundError:
        # If salt file does not exist, prompt user for salt
        salt_input = input("Salt file not found. Please enter the salt in hexadecimal: ")
        salt = bytes.fromhex(salt_input.strip())
    
    # Derive AES key from password and salt
    encryption_key = derive_key(password, salt)

    try:
        with open(nonce_key, 'rb') as kf:
            nonce = kf.read()
    except FileNotFoundError:
        # If nonce file does not exist, prompt user for nonce
        nonce_input = input("Nonce file not found. Please enter the nonce in hexadecimal: ")
        nonce = bytes.fromhex(nonce_input.strip())

    try:
        with open(tag_key, 'rb') as kf:
            tag = kf.read()
    except FileNotFoundError:
        # If tag file does not exist, prompt user for tag
        tag_input = input("Tag file not found. Please enter the tag in hexadecimal: ")
        tag = bytes.fromhex(tag_input.strip())

    # Create AES cipher for decryption
    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and unpad the key
    padded_data = decryptor.update(encrypted_key) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_key = unpadder.update(padded_data) + unpadder.finalize()

    return decrypted_key.decode()

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
    aes_key = 'aes.key'
    nonce_key = 'nonce.key'
    tag_key = 'tag.key'
    
    # Create key files if they don't exist
    create_key_file(aes_key, 32)  # 32 bytes for AES-256
    create_key_file(nonce_key, 16)  # 16 bytes for nonce
    create_key_file(tag_key, 16)  # 16 bytes for GCM tag

    action = input("Do you want to (e)ncrypt a new key or (d)ecrypt an existing one? (e/d): ").lower()
    
    if action == 'e':
        private_key = input("Enter your private key to encrypt: ")
        password = getpass.getpass("Enter a password to secure the key: ")
        encrypted_key, nonce, tag, salt = encrypt_key(private_key, password, aes_key, nonce_key, tag_key)

        # Print keys for backup
        with open(aes_key, 'rb') as kf:
            encryption_key = kf.read()
        print(f"AES Key (in hexadecimal): {encryption_key.hex()}")  # Display AES key in hexadecimal
        
        print(f"Nonce (in hexadecimal): {nonce.hex()}")  # Display Nonce in hexadecimal
        print(f"Tag (in hexadecimal): {tag.hex()}")      # Display Tag in hexadecimal
        print(f"Salt (in hexadecimal): {salt.hex()}")    # Display Salt in hexadecimal

        # Upload to Google Drive
        folder_id = '1js7SqUpbqIoEFAT1HX8lX67JTGJwwZH0'  # Keys folder under My Drive
        upload_to_drive('topo.txt', encrypted_key, folder_id)
        
        print("Encrypted key uploaded to Google Drive.")

    elif action == 'd':
        file_id = input("Enter the Google Drive file ID to download: ")
        download_from_drive(file_id, 'topo.txt')
        
        # Read the downloaded encrypted key
        with open('topo.txt', 'rb') as file:
            encrypted_key = file.read()

        # Decrypt the key
        password = getpass.getpass("Enter the password to decrypt the key: ")
        decrypted_key = decrypt_key(encrypted_key, password, nonce_key, tag_key)
        print(f"Decrypted Key: {decrypted_key}")

if __name__ == '__main__':
    main()
