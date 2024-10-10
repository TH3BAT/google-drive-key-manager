import os
from googleapiclient.discovery import build
from google.oauth2.service_account import Credentials

# Set up the API credentials
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'client_secrets.json'  # Path to your service account JSON

def authenticate_gdrive():
    credentials = Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    service = build('drive', 'v3', credentials=credentials)
    return service

def list_files(service):
    results = service.files().list(
        pageSize=10, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])
    return items

def delete_file(service, file_id):
    service.files().delete(fileId=file_id).execute()
    print(f'File with ID {file_id} deleted successfully.')

def main():
    service = authenticate_gdrive()
    files = list_files(service)

    if not files:
        print('No files found.')
    else:
        print('Files:')
        for file in files:
            print(f"{file['name']} (ID: {file['id']})")

        # Prompt to delete files
        file_ids_to_delete = input('Enter the IDs of files to delete, separated by commas: ')
        for file_id in file_ids_to_delete.split(','):
            delete_file(service, file_id.strip())

if __name__ == '__main__':
    main()
