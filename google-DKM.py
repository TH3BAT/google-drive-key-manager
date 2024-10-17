"""
This module provides a secure framework for encrypting and decrypting sensitive data, specifically private keys, using AES-256 encryption. 
It integrates with the Google Drive API for seamless storage and retrieval of encrypted files.

 Key Features:
   - **Key Derivation**: Utilizes bcrypt with a unique salt for deriving a secure encryption key from a user-provided password, providing 
     strong protection against brute-force and rainbow table attacks.

   - **Encryption**: Supports AES-256 encryption in GCM mode, ensuring both confidentiality and integrity of the encrypted data. Encryption 
     components (salt, nonce, tag, and ciphertext) are combined into a single file for simplified management.

   - **File Handling and Permissions**: Automatically manages the creation of a combined key file (including salt, nonce, tag, and encrypted 
     data) and saves it with secure `600` permissions (read/write for the owner only).

   - **Google Drive Integration**: Allows for secure uploading and downloading of encrypted files to and from Google Drive, enabling easy 
     access to stored sensitive data while keeping it encrypted.

   - **Hex Conversion Support**: Provides an option for converting individual AES keys, nonces, tags, and salts from hexadecimal values into a 
     single combined key format for easy handling.

   - **User Input Management**: Utilizes secure password prompts to prevent exposure of sensitive information during key encryption and 
     decryption processes. The user can convert existing encryption parameters into the new format or decrypt using the combined key.

 Usage:
  1. Run the module and choose one of the following:
     - (e)ncrypt a new key: Input your private key and a password to generate an encrypted file stored securely with `600` permissions and 
       uploaded to Google Drive.
     - (d)ecrypt an existing key: Download the encrypted file from Google Drive and input the password to retrieve your private key.
     - (c)onvert hex to combined key: Input existing AES key, nonce, tag, and salt in hexadecimal format to generate a new combined key file.

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
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from rich.progress import Progress
from rich.console import Console
from rich.spinner import Spinner

# Constants for Google Drive API
SCOPES = ['https://www.googleapis.com/auth/drive.file']
SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_SERVICE_ACCOUNT_FILE', 'client_secrets.json')

console = Console()


def authenticate_drive():
    """
    Authenticate and build the Google Drive service client.

    Returns:
        drive_service: The authenticated Google Drive service client.
    """
    try:
        creds = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
        drive_service = build('drive', 'v3', credentials=creds)
        return drive_service
    except Exception as e:
        console.print(f"[red]Failed to authenticate Google Drive: {e}")
        raise


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a key from a password using bcrypt.

    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt used for key derivation.

    Returns:
        bytes: The derived key.
    """
    return bcrypt.kdf(password.encode(), salt, desired_key_bytes=32, rounds=100000)


def create_combined_key_file(file_name: str, combined_key: bytes):
    """
    Write the combined key to a file with secure permissions.

    Args:
        file_name (str): The name of the file to create.
        combined_key (bytes): The combined key to write to the file.
    """
    try:
        with open(file_name, 'wb') as f:
            f.write(combined_key)
        os.chmod(file_name, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        console.print(f"[red]Error writing combined key file: {e}")
        raise


def encrypt_key(key: str, password: str) -> bytes:
    """
    Encrypt the key using AES-256 encryption and combine all components into one file.

    Args:
        key (str): The key to encrypt.
        password (str): The password used for encryption.

    Returns:
        bytes: The combined encrypted key components.
    """
    salt = bcrypt.gensalt()
    encryption_key = derive_key(password, salt)
    nonce = os.urandom(16)

    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(key.encode()) + padder.finalize()
    encrypted_key = encryptor.update(padded_data) + encryptor.finalize()
    tag = encryptor.tag

    combined_key = salt + nonce + tag + encrypted_key
    return combined_key


def decrypt_key(combined_key: bytes, password: str) -> str:
    """
    Decrypt the key using AES-256 from the combined key file.

    Args:
        combined_key (bytes): The combined key to decrypt.
        password (str): The password used for decryption.

    Returns:
        str: The decrypted key.
    """
    salt = combined_key[:29]
    nonce = combined_key[29:45]
    tag = combined_key[45:61]
    encrypted_key = combined_key[61:]

    encryption_key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_key) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_key = unpadder.update(padded_data) + unpadder.finalize()

    return decrypted_key.decode()


def convert_hex_to_combined_key(hex_aes_key: str, hex_nonce: str, hex_tag: str, hex_salt: str) -> bytes:
    """
    Convert hexadecimal values to combined key format.

    Args:
        hex_aes_key (str): AES key in hexadecimal.
        hex_nonce (str): Nonce in hexadecimal.
        hex_tag (str): Tag in hexadecimal.
        hex_salt (str): Salt in hexadecimal.

    Returns:
        bytes: The combined key in bytes.
    """
    salt = bytes.fromhex(hex_salt)
    nonce = bytes.fromhex(hex_nonce)
    tag = bytes.fromhex(hex_tag)
    aes_key = bytes.fromhex(hex_aes_key)
    
    return salt + nonce + tag + aes_key


def upload_to_drive(file_name: str, content: bytes, folder_id: str = None):
    """
    Upload a file to Google Drive with progress tracking.

    Args:
        file_name (str): The name of the file to upload.
        content (bytes): The content to write to the file.
        folder_id (str, optional): The ID of the Google Drive folder to upload to. Defaults to None.

    Raises:
        Exception: If an error occurs during file upload or Drive API interaction.
    """
    try:
        drive_service = authenticate_drive()
        
        # Create the file locally
        with open(file_name, 'wb') as file:
            file.write(content)

        # File metadata for Google Drive
        file_metadata = {'name': file_name}
        if folder_id:
            file_metadata['parents'] = [folder_id]

        # Prepare the file for upload with a MediaIoBaseUpload for progress tracking
        media = MediaIoBaseUpload(io.BytesIO(content), mimetype='text/plain', resumable=True)

        with Progress() as progress:
            task = progress.add_task("[green]Uploading to Google Drive...", total=len(content))

            # Create a request to upload the file
            request = drive_service.files().create(body=file_metadata, media_body=media, fields='id')

            # Monitor the upload process
            while True:
                status = request.next_chunk()
                if status:
                    progress.update(task, advance=status.bytes_uploaded)
                    if status.done():
                        break

        console.print(f"[green]File uploaded successfully to folder ID {folder_id}. File ID: {uploaded_file['id']}")
        
    except Exception as e:
        console.print(f"[red]Error uploading file to Google Drive: {e}")


def download_from_drive(file_id: str, file_name: str):
    """
    Download a file from Google Drive.

    Args:
        file_id (str): The ID of the file to download.
        file_name (str): The name to save the downloaded file as.

    Raises:
        Exception: If an error occurs during the download process.
    """
    try:
        drive_service = authenticate_drive()
        request = drive_service.files().get_media(fileId=file_id)

        with open(file_name, 'wb') as file:
            downloader = MediaIoBaseDownload(file, request)
            spinner = Spinner('dots', text="Downloading from Google Drive...")

            # Start the spinner and download process
            console.print(spinner)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                progress = int(status.progress() * 100)
                console.log(f"Download {progress}% complete.")

        console.print("[green]Download complete!")

    except Exception as e:
        console.print(f"[red]Error downloading file from Google Drive: {e}")


def main():
    """
    Main function to handle user actions: encrypting, decrypting, and converting keys.
    """
    combined_key_file = 'combined.key'

    action = input("Do you want to (e)ncrypt a new key, (d)ecrypt an existing one, or (c)onvert hex to combined key? (e/d/c): ").lower()

    if action == 'e':
        private_key = input("Enter your private key to encrypt: ")
        password = getpass.getpass("Enter a password to secure the key: ")

        with Progress() as progress:
            task = progress.add_task("[green]Generating key...", total=100)
            combined_key = encrypt_key(private_key, password)
            for percent in range(100):
                progress.update(task, advance=1)

        create_combined_key_file(combined_key_file, combined_key)

        console.print(f"[green]Combined key saved to {combined_key_file} with secure permissions.")

        # Display hex representations of the combined key components
        with open(combined_key_file, 'rb') as file:
            combined_key = file.read()

        salt = combined_key[:29]
        nonce = combined_key[29:45]
        tag = combined_key[45:61]
        encrypted_key = combined_key[61:]
        
        console.print(f"AES Key (in hexadecimal): {encrypted_key.hex()}")
        console.print(f"Nonce (in hexadecimal): {nonce.hex()}")
        console.print(f"Tag (in hexadecimal): {tag.hex()}")
        console.print(f"Salt (in hexadecimal): {salt.hex()}")

        folder_id = input("Enter the Google Drive folder ID to upload the file to (leave empty for root): ") or None
        upload_to_drive(combined_key_file, combined_key, folder_id)

    elif action == 'd':
        file_id = input("Enter the Google Drive file ID to download: ")
        download_from_drive(file_id, combined_key_file)

        with open(combined_key_file, 'rb') as file:
            combined_key = file.read()

        password = getpass.getpass("Enter the password to decrypt the key: ")
        decrypted_key = decrypt_key(combined_key, password)

        console.print(f"[green]Decrypted key: {decrypted_key}")

    elif action == 'c':
        hex_aes_key = input("Enter the AES key in hexadecimal: ")
        hex_nonce = input("Enter the Nonce in hexadecimal: ")
        hex_tag = input("Enter the Tag in hexadecimal: ")
        hex_salt = input("Enter the Salt in hexadecimal: ")

        combined_key = convert_hex_to_combined_key(hex_aes_key, hex_nonce, hex_tag, hex_salt)
        create_combined_key_file(combined_key_file, combined_key)
        console.print(f"[green]Combined key from hex values saved to {combined_key_file}.")

    else:
        console.print("[red]Invalid option. Please select (e), (d), or (c).")


if __name__ == "__main__":
    main()
