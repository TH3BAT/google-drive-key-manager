"""
This module provides a secure framework for encrypting and decrypting sensitive data, specifically private keys, using AES-256 encryption.
It integrates with the Google Drive API for seamless storage and retrieval of encrypted files.

Key Features:
   - **Key Derivation**: Utilizes bcrypt with a unique salt to derive a secure encryption key from a user-provided password, providing strong
     protection against brute-force and rainbow table attacks.

   - **Encryption**: Supports AES-256 encryption in GCM mode, ensuring both confidentiality and integrity of the encrypted data. Encryption
     components (salt, nonce, tag, and ciphertext) are combined into a single file for simplified management.

   - **File Handling and Permissions**: Automatically manages the creation of a combined key file (including salt, nonce, tag, and encrypted
     data) and saves it with secure `600` permissions (read/write for the owner only).

   - **Google Drive Integration**: Allows for secure uploading and downloading of encrypted files to and from Google Drive, enabling easy
     access to stored sensitive data while keeping it encrypted.

   - **Hex Conversion Support**: Provides an option to enter individual AES components (key, nonce, tag, and salt) in hexadecimal format if
     the combined key file is lost. This feature allows users to recreate the combined key directly, adding a secondary recovery method.

   - **User Input Management**: Utilizes secure password prompts to prevent exposure of sensitive information during key encryption and
     decryption processes. The user can either convert existing encryption parameters into the new format or decrypt using the combined key.

Usage:
  1. Run the module and choose one of the following:
     - (e)ncrypt a new key: Input your private key and a password to generate an encrypted file stored securely with `600` permissions and
       uploaded to Google Drive.
     - (d)ecrypt an existing key: Download the encrypted file from Google Drive or manually input hex values if the file is missing, then
       enter the password to retrieve your private key.
     - (c)onvert hex to combined key: Input existing AES key, nonce, tag, and salt in hexadecimal format to generate a new combined key file
       for backup.

Dependencies:
  - Requires the `cryptography` library for cryptographic operations.
  - Requires the `google-api-python-client` library for Google Drive API interactions.
  
Note: Ensure you have a valid Google service account with appropriate permissions and the `client_secrets.json` file for Google Drive
authentication.
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
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from typing import Optional

# Constants for Google Drive API
SCOPES = ['https://www.googleapis.com/auth/drive.file']
SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_SERVICE_ACCOUNT_FILE', 'client_secrets.json')

console = Console()

# Authentication function for Google Drive API
def authenticate_drive():
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    return build('drive', 'v3', credentials=credentials)

# Function to encrypt the key with password protection
def encrypt_key(private_key: str, password: str) -> bytes:
    salt = bcrypt.gensalt()
    aes_key = bcrypt.kdf(password.encode(), salt, 32, 100000)
    nonce = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    padded_key = padder.update(private_key.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(padded_key) + encryptor.finalize()
    tag = encryptor.tag
    console.print(f"AES Key (hex): {encrypted_key.hex()}")
    console.print(f"Nonce (hex): {nonce.hex()}")
    console.print(f"Tag (hex): {tag.hex()}")
    console.print(f"Salt (hex): {salt.hex()}")
    return salt + nonce + tag + encrypted_key

# Function to decrypt the key using password
def decrypt_key(combined_key: bytes, password: str) -> Optional[str]:
    salt = combined_key[:29]
    nonce = combined_key[29:45]
    tag = combined_key[45:61]
    encrypted_key = combined_key[61:]
    aes_key = bcrypt.kdf(password.encode(), salt, 32, 100000)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_key = decryptor.update(encrypted_key) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_key) + unpadder.finalize()).decode()

# Function to save combined key file securely
def create_combined_key_file(file_name: str, combined_key: bytes):
    with open(file_name, 'wb') as file:
        file.write(combined_key)
    os.chmod(file_name, stat.S_IREAD | stat.S_IWRITE)

# Function to upload file to Google Drive
def upload_to_drive(file_name: str, content: bytes, folder_id: str = None):
    try:
        drive_service = authenticate_drive()
        with open(file_name, 'wb') as file:
            file.write(content)
        file_metadata = {'name': file_name}
        if folder_id:
            file_metadata['parents'] = [folder_id]
        media = MediaIoBaseUpload(io.BytesIO(content), mimetype='text/plain', resumable=True)
        with console.status("[bold green]Uploading to Google Drive..."):
            request = drive_service.files().create(body=file_metadata, media_body=media, fields='id')
            while True:
                upload_status, response = request.next_chunk()
                if response:
                    console.print(f"[green]File uploaded successfully. File ID: {response.get('id')}")
                    break
    except Exception as e:
        console.print(f"[red]Error uploading file to Google Drive: {e}")

# Function to download a file from Google Drive
def download_from_drive(file_id: str, destination: str):
    try:
        drive_service = authenticate_drive()
        request = drive_service.files().get_media(fileId=file_id)
        fh = io.FileIO(destination, 'wb')
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        with console.status("[bold green]Downloading file from Google Drive..."):
            while not done:
                status, done = downloader.next_chunk()
                console.print(f"Download progress: {int(status.progress() * 100)}%", end='\r')
        console.print("[green]File downloaded successfully.")
    except Exception as e:
        console.print(f"[red]Error downloading file from Google Drive: {e}")

# Main function to handle user actions
def main():
    combined_key_file = 'combined.key'
    action = input("Do you want to (e)ncrypt a new key, (d)ecrypt an existing one, or (q)uit? (e/d/q): ").lower()
    if action == 'e':
        # Encrypting and saving the key
        private_key = input("Enter your private key to encrypt: ")
        password = getpass.getpass("Enter a password to secure the key: ")
        with console.status("[bold green]Encrypting key..."):
            combined_key = encrypt_key(private_key, password)
        create_combined_key_file(combined_key_file, combined_key)
        console.print(f"[green]Combined key saved to {combined_key_file}.")
        folder_id = input("Enter Google Drive folder ID (or press Enter for root): ") or None
        upload_to_drive(combined_key_file, combined_key, folder_id)

    elif action == 'd':
        # Decrypting an existing key
        file_id = input("Enter the Google Drive file ID to download (or press Enter to skip): ")
        if file_id:
            download_from_drive(file_id, combined_key_file)

        # Load the combined key from file or manual input
        if os.path.exists(combined_key_file):
            with open(combined_key_file, 'rb') as file:
                combined_key = file.read()
        else:
            console.print("[red]Combined key file not found. Please enter each hex value manually.")
            salt_hex = input("Enter the Salt (hex): ")
            nonce_hex = input("Enter the Nonce (hex): ")
            tag_hex = input("Enter the Tag (hex): ")
            encrypted_key_hex = input("Enter the Encrypted Key (hex): ")
            
            # Convert hex inputs to bytes
            salt = bytes.fromhex(salt_hex)
            nonce = bytes.fromhex(nonce_hex)
            tag = bytes.fromhex(tag_hex)
            encrypted_key = bytes.fromhex(encrypted_key_hex)
            combined_key = salt + nonce + tag + encrypted_key

        # Password prompt and decryption
        password = getpass.getpass("Enter the password to decrypt the key: ")
        with console.status("[bold green]Decrypting key..."):
            decrypted_key = decrypt_key(combined_key, password)
        if decrypted_key:
            console.print(f"[green]Decrypted key: {decrypted_key}")
        else:
            console.print("[red]Decryption failed. Please check your password and hex values.")

    elif action == 'q':
        console.print("[blue]Goodbye!")
    else:
        console.print("[red]Invalid option. Please select (e), (d), or (q).")

if __name__ == "__main__":
    main()
