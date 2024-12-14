import os
import pickle
import sys
import io
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QFileDialog
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from PyQt5.QtGui import QPixmap, QIcon

def set_dark_theme(self):
        """Set dark theme for the application."""
        dark_stylesheet = """
        QWidget {
            background-color: #2b2b2b;
            color: #d3d3d3;
        }

        QLineEdit, QTextEdit, QPlainTextEdit {
            background-color: #3c3f41;
            color: #d3d3d3;
            border: 1px solid #444444;
            padding: 5px;
        }

        QPushButton {
            background-color: #4a4a4a;
            color: #d3d3d3;
            border: 1px solid #5a5a5a;
            padding: 5px 15px;
        }

        QPushButton:hover {
            background-color: #5a5a5a;
        }

        QPushButton:pressed {
            background-color: #6a6a6a;
        }

        QListWidget {
            background-color: #3c3f41;
            color: #d3d3d3;
            border: 1px solid #444444;
        }

        QProgressBar {
            background-color: #444444;
            border: 1px solid #555555;
            border-radius: 10px;  /* Makes the edges rounded */
            text-align: center;
            height: 20px;  /* Adjust the height */
        }

        QProgressBar::chunk {
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0, 
                stop: 0 #4CAF50, stop: 1 #8BC34A);  /* Gradient from green to light green */
            border-radius: 10px;  /* Makes the progress chunk's edges rounded */
            width: 20px;
        }

        QTabWidget::pane {
            border: 1px solid #444444;
            background-color: #2b2b2b;
        }

        QTabBar::tab {
            background-color: #3c3f41;
            color: #d3d3d3;
            padding: 10px;
        }

        QTabBar::tab:selected {
            background-color: #4a4a4a;
            color: white;
        }

        QTableWidget {
            background-color: #3c3f41;
            color: #d3d3d3;
            border: 1px solid #444444;
        }

        QTableWidget::item {
            padding: 5px;
        }

        QGroupBox {
            border: 1px solid #444444;
            background-color: #2b2b2b;
            color: #d3d3d3;
            margin: 5px;
            padding: 10px;
        }

        QFormLayout {
            background-color: #2b2b2b;
            color: #d3d3d3;
        }
        """
        self.setStyleSheet(dark_stylesheet)

# Scope for file management
SCOPES = ['https://www.googleapis.com/auth/drive.file']

# The file you want to back up
FILE_PATH = 'password_manager.db'
BACKUP_FOLDER_NAME = 'Password Manager Backups'  # Folder name for backups

# Authenticate and create the service
def authenticate_google_account():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('drive', 'v3', credentials=creds)
    return service

# Check if the backup folder exists in Google Drive, or create it
def check_for_backup_folder(service):
    query = f"name = '{BACKUP_FOLDER_NAME}' and mimeType = 'application/vnd.google-apps.folder'"
    results = service.files().list(q=query).execute()
    items = results.get('files', [])

    if items:
        folder_id = items[0]['id']
    else:
        file_metadata = {'name': BACKUP_FOLDER_NAME, 'mimeType': 'application/vnd.google-apps.folder'}
        folder = service.files().create(body=file_metadata, fields='id').execute()
        folder_id = folder['id']
    
    return folder_id

# Upload the file to Google Drive
def upload_file_to_drive(service, folder_id):
    file_metadata = {'name': os.path.basename(FILE_PATH), 'parents': [folder_id]}
    media = MediaFileUpload(FILE_PATH, mimetype='application/octet-stream')

    # Upload the file to the backup folder
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f'File {FILE_PATH} uploaded to Google Drive with file ID: {file["id"]}')

# Retrieve the latest version of the file from Google Drive if not present locally
def retrieve_latest_file(service, folder_id):
    # Search for the most recent file in the backup folder
    query = f"'{folder_id}' in parents and name = '{os.path.basename(FILE_PATH)}'"
    results = service.files().list(q=query, orderBy="modifiedTime desc", pageSize=1).execute()
    items = results.get('files', [])

    if items:
        file_id = items[0]['id']
        file_name = items[0]['name']
        print(f"Found the latest version of {file_name} on Google Drive. Downloading...")

        # Download the file from Google Drive
        request = service.files().get_media(fileId=file_id)
        fh = io.FileIO(FILE_PATH, 'wb')
        downloader = MediaIoBaseDownload(fh, request)
        
        done = False
        while done is False:
            status, done = downloader.next_chunk()
            print(f"Download {int(status.progress() * 100)}%.")
        
        print(f"File {file_name} downloaded successfully.")
    else:
        print(f"No file found on Google Drive named {os.path.basename(FILE_PATH)}.")

# Delete the local file after backup
def delete_local_file():
    if os.path.exists(FILE_PATH):
        os.remove(FILE_PATH)
        print(f"Local file {FILE_PATH} deleted after backup.")

class BackupApp(QWidget):
    def __init__(self):
        super().__init__()

        # Set up the window
        self.setWindowTitle("PassGuardX Backup")
        self.setGeometry(100, 100, 200, 200)
        self.setWindowOpacity(0.9)

        # Set the dark theme
        set_dark_theme(self)

        icon_path = self.find_icon('ICON/icons8-app-50.png')  # Try to find the icon

        # Set the icon if it's found, otherwise use a fallback
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))
        else:
            self.setWindowIcon(QIcon('ICON/icons8-app-50.png'))
        
        # Layout and widgets
        self.layout = QVBoxLayout()

        self.info_label = QLabel("Are you sure you want to backup!", self)
        self.layout.addWidget(self.info_label)

        self.backup_button = QPushButton("Backup", self)
        self.backup_button.clicked.connect(self.backup_file)
        self.layout.addWidget(self.backup_button)

        self.setLayout(self.layout)

    def find_icon(self, icon_name):
        """Attempts to find the icon in and out of the script's directory."""
        script_dir = os.path.dirname(os.path.realpath(__file__))

        possible_paths = [
            os.path.join(script_dir, icon_name),
            os.path.join(script_dir, 'ICON', icon_name),
            os.path.abspath(os.path.join(script_dir, os.pardir, icon_name)),
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        return None

    def backup_file(self):
        # Authenticate and create the service
        service = authenticate_google_account()

        # Check or create the backup folder
        folder_id = check_for_backup_folder(service)

        # Check if the local file exists
        if os.path.exists(FILE_PATH):
            # If the file exists, upload it to Google Drive
            upload_file_to_drive(service, folder_id)
            # Delete the local file after backup
            delete_local_file()
            self.info_label.setText(f"File '{FILE_PATH}' backed up and deleted.")
        else:
            # If the file does not exist, retrieve it from Google Drive
            retrieve_latest_file(service, folder_id)
            self.info_label.setText(f"File '{FILE_PATH}' retrieved from Google Drive.")

# Main function to start the app
def main():
    app = QApplication(sys.argv)
    window = BackupApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
