import sys
import bcrypt
import sqlite3
import pyotp
import qrcode
import random
import ssl
import io
import json
import pickle
import base64
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem, QInputDialog, QMessageBox, QLabel, QDialog, QAction
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtCore import Qt
import subprocess
from PyQt5.QtGui import QFont
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
import smtplib
import random
import logging
import requests
import ssl
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from hashlib import sha256
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from Alpha_Pass import PasswordGeneratorApp
from backup import BackupApp
import google.auth
import google.auth.credentials
from PIL import Image, ImageQt 
from Cryptodome.Util.Padding import pad, unpad

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Define constants for encryption
ENCRYPTION_KEY = os.urandom(32)  # Use a fixed key or store it securely for real implementations.

HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount"


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
        

def log_message(message):
    """Logs the message to both the QTextEdit and the log file."""
    with open("sync_log.txt", "a") as log_file:
        log_file.write(message + "\n")

def show_message(title, message, message_type):
    """Displays a message box to provide feedback to the user."""
    msg = QMessageBox()
    msg.setWindowTitle(title)
    msg.setText(message)
    
    # Set the icon based on message type
    if message_type == "info":
        msg.setIcon(QMessageBox.Information)
    elif message_type == "error":
        msg.setIcon(QMessageBox.Critical)
    
    # Path to the icon you want to use
    icon_path = find_icon('ICON/icons8-app-50.png')
    
    # Check if the icon file exists, and set it accordingly
    if icon_path:
        msg.setWindowIcon(QIcon(icon_path))
    else:
        msg.setWindowIcon(QIcon('ICON/icons8-app-50.png'))  # Fallback icon
    
    # Display the message box
    msg.exec_()

def find_icon(icon_name):
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

# Scope for file management
SCOPES = ['https://www.googleapis.com/auth/drive.file']

# The file you want to retrieve
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

# Retrieve the latest version of the file from Google Drive if not present locally
def retrieve_latest_file(service, folder_id):
    if os.path.exists(FILE_PATH):
        print(f"Local file {FILE_PATH} already exists.")
        return  # File already exists, no need to retrieve from Drive.

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

# Create database if it doesn't exist
def create_database():
    """Creates the database and tables if they don't exist, and updates schema if needed."""
    try:
        if os.path.exists(FILE_PATH):
            log_message("Database file already exists.")
        else:
            log_message("Creating database and tables...")

            # Connect to SQLite database (it will create the database file if it doesn't exist)
            conn = sqlite3.connect(FILE_PATH)
            cursor = conn.cursor()

            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    email TEXT UNIQUE,
                    hashed_password TEXT,
                    secret_key TEXT,
                    recovery_codes TEXT
                );
            """)

            # Create credentials table with user_id as a foreign key to users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website TEXT,
                    username TEXT,
                    password TEXT,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
            """)

            # Add the 'secret_key' and 'recovery_codes' columns to the users table if they don't already exist
            try:
                cursor.execute("PRAGMA table_info(users);")
                columns = cursor.fetchall()
                column_names = [column[1] for column in columns]
                if "secret_key" not in column_names:
                    cursor.execute("ALTER TABLE users ADD COLUMN secret_key TEXT;")
                    log_message("Added 'secret_key' column to users table.")
                if "recovery_codes" not in column_names:
                    cursor.execute("ALTER TABLE users ADD COLUMN recovery_codes TEXT;")
                    log_message("Added 'recovery_codes' column to users table.")
            except sqlite3.Error as e:
                log_message(f"Error adding columns: {e}")

            # Commit the changes and close the connection
            conn.commit()
            conn.close()
            log_message("Database and tables created successfully.")
    except sqlite3.Error as e:
        log_message(f"Database error: {e}")
        error_message = f"Database error: {e}"
        log_message(error_message)
        show_message("Error", error_message, "error")
    except Exception as e:
        log_message(f"An error occurred while creating the database: {e}")
        error_message = f"An error occurred while creating the database: {e}"
        log_message(error_message)
        show_message("Error", error_message, "error")

# Hashing user passwords
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Verifying user passwords
def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

# Encrypt password using AES
def encrypt_password(password, master_password):
    key = PBKDF2(master_password.encode('utf-8'), b'salt', dkLen=32)  # Use a salt and PBKDF2 for key derivation
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    
    # Store ciphertext, nonce, and tag (all base64 encoded)
    encrypted_data = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
    return encrypted_data

# Decrypt password using AES
def decrypt_password(encrypted_data, master_password):
    encrypted_data = base64.b64decode(encrypted_data)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    
    key = PBKDF2(master_password.encode('utf-8'), b'salt', dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
    
    return decrypted_password.decode('utf-8')


# Email Verification
def send_verification_email(user_email, verification_code):
    port = 465  # SSL port for Gmail
    smtp_server = "smtp.gmail.com"
    sender_email = "alphadefenderx@gmail.com"  # Replace with your Gmail
    password = "cexh ifur fguk jlyy"  # Replace with your email password (or app password if 2FA is enabled)
    
    # Create the email content
    subject = "Email Verification Code"
    body = f"Your verification code is: {verification_code}"
    
    # Set up the MIME message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = user_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))
    
    # Send the email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, user_email, message.as_string())

# PyQt5 Main Window for managing the application
class PasswordManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('PassGuard')
        self.setGeometry(100, 100, 800, 600)
        self.setWindowOpacity(0.9)

        service = authenticate_google_account()
        folder_id = check_for_backup_folder(service)
        retrieve_latest_file(service, folder_id)  # Retrieve the latest file from Google Drive
        create_database()  # Ensure the database is created if not present

        # Set the dark theme
        set_dark_theme(self)

        icon_path = self.find_icon('ICON/icons8-app-50.png')  # Try to find the icon

        # Set the icon if it's found, otherwise use a fallback
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))
        else:
            self.setWindowIcon(QIcon('ICON/icons8-app-50.png'))
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        layout = QVBoxLayout()

        # Create a QLineEdit to act as the title
        self.title_input = QLineEdit(self)
        self.title_input.setText("Welcome To PassGuard")  # Text to display as title
        self.title_input.setAlignment(Qt.AlignCenter)  # Center align the text inside QLineEdit
        self.title_input.setReadOnly(True)  # Make it non-editable, like a label
        self.title_input.setStyleSheet("background-color: transparent; color: #d3d3d3; font-size: 36px; font-weight: bold; border: none;")

        # Add both the icon label and the title input field to the header layout
        
        layout.addWidget(self.title_input)  # Add the title input (right side)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText('Username')
        layout.addWidget(self.username_input)
        
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('Password')
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)
        
        self.login_button = QPushButton('Login', self)
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)
        
        self.sign_up_button = QPushButton('Sign Up', self)
        self.sign_up_button.clicked.connect(self.open_sign_up)
        layout.addWidget(self.sign_up_button)
        
        self.central_widget.setLayout(layout)

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
    
    def use_recovery_code(self, entered_code):
        """Allow user to authenticate using a recovery code"""
        if entered_code in self.recovery_codes:
            self.recovery_codes.remove(entered_code)  # Remove used recovery code
            return True
        return False

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password(user[3], password):  # user[3] is the hashed password
            # Prompt for 2FA code after password check
            totp = pyotp.TOTP(user[4])  # user[4] is the secret key
            otp = QInputDialog.getText(self, '2FA Authentication', 'Enter the OTP from your authenticator app:')[0]

            if totp.verify(otp):
                QMessageBox.information(self, "Success", "Login successful!")
                user_id = user[0]  # Get user_id
                self.open_password_manager(user_id)  # Pass user_id to password manager
            else:
                # Allow the user to use a recovery code if 2FA fails
                recovery_code, ok = QInputDialog.getText(self, 'Recovery Code', 'Enter your recovery code:')
                if ok and self.use_recovery_code(recovery_code):
                    QMessageBox.information(self, "Success", "Login successful with recovery code!")
                    user_id = user[0]
                    self.open_password_manager(user_id)
                else:
                    QMessageBox.information(self, "Failed", "Invalid OTP or recovery code. Please try again.")
        else:
            QMessageBox.information(self, "Warning", "Invalid credentials")

        conn.close()

    def open_sign_up(self):
        self.sign_up_window = SignUpPage()
        self.sign_up_window.show()

    def open_password_manager(self, user_id):
        self.password_manager_window = PasswordManagerWindow(user_id)
        self.password_manager_window.show()
        self.close()

class SignUpPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Sign Up')
        self.setWindowOpacity(0.9)
        set_dark_theme(self)

        icon_path = self.find_icon('ICON/icons8-app-50.png')  # Try to find the icon
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))
        else:
            self.setWindowIcon(QIcon('ICON/icons8-app-50.png'))

        layout = QVBoxLayout()

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText('Username')
        layout.addWidget(self.username_input)

        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText('Email')
        layout.addWidget(self.email_input)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('Password')
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.sign_up_button = QPushButton('Sign Up', self)
        self.sign_up_button.clicked.connect(self.sign_up)
        layout.addWidget(self.sign_up_button)

        self.setLayout(layout)

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
    
    def generate_recovery_codes(self, num_codes=5):
        """Generate recovery codes for backup purposes"""
        recovery_codes = []
        for _ in range(num_codes):
            code = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8').rstrip("=")
            recovery_codes.append(code)
        return recovery_codes

    def sign_up(self):
        username = self.username_input.text()
        email = self.email_input.text()
        password = self.password_input.text()

        # Connect to the database
        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_username = cursor.fetchone()

        if existing_username:
            QMessageBox.information(self, "Attention!", "Username is already taken. Please choose a different username.")
            conn.close()  # Close the connection
            return  # Exit the function, preventing further execution

        # Generate a unique 6-digit verification code
        verification_code = random.randint(100000, 999999)

        # Send the verification email
        try:
            send_verification_email(email, verification_code)
            QMessageBox.information(self, "Verification", f"Verification code sent to {email}")
        except Exception as e:
            QMessageBox.information(self, "Email sending error", f"Error sending email: {e}")
            conn.close()  # Ensure to close the connection if email fails
            return

        # Prompt user for the code
        entered_code, ok = QInputDialog.getText(self, 'Verification', 'Enter the verification code sent to your email:')
        if ok and str(entered_code) == str(verification_code):
            QMessageBox.information(self, "Authentication Success", "Verification successful!")
            self.register_user(username, email, password)
        else:
            QMessageBox.information(self, "Invalid verification code", "Invalid verification code.")

        conn.close()  # Ensure the connection is closed

    def register_user(self, username, email, password):
        # Connect to the database
        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()

        # Check if the email already exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            QMessageBox.information(self, "Attention!", "Email is already registered. Please choose a different email.")
            conn.close()
            return False

        # Hash the password before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Generate the 2FA secret key and QR code
        totp = pyotp.TOTP(pyotp.random_base32())
        secret_key = totp.secret
        uri = totp.provisioning_uri(username, issuer_name="PassGuard")

            # Generate the QR code (without the icon first)
        qr = qrcode.make(uri)
        qr = qr.convert('RGB')  # Ensure it's in RGB mode (needed for blending the icon)

        # Load the icon image
        icon_path = self.find_icon('icons8-app-50.png')  # Change this to your actual icon path
        icon = Image.open(icon_path)

        # Resize the icon to fit in the center of the QR code (optional, adjust as needed)
        icon_size = qr.size[0] // 5  # Resize icon to 1/5th of QR code size
        icon = icon.resize((icon_size, icon_size))

        # Calculate the position to center the icon in the QR code
        qr_width, qr_height = qr.size
        icon_width, icon_height = icon.size
        position = ((qr_width - icon_width) // 2, (qr_height - icon_height) // 2)

        # Paste the icon onto the QR code
        qr.paste(icon, position, icon.convert('RGBA'))

        qr.show()

        # Generate recovery codes
        recovery_codes = self.generate_recovery_codes()

        # Insert the new user into the database with the 2FA secret key and recovery codes
        try:
            cursor.execute("INSERT INTO users (username, email, hashed_password, secret_key, recovery_codes) VALUES (?, ?, ?, ?, ?)", 
                        (username, email, hashed_password, secret_key, json.dumps(recovery_codes)))
            conn.commit()
            QMessageBox.information(self, "Success", "User registered successfully! Please set up your 2FA in your authenticator app.")
            self.close()  # Close the sign-up window after successful registration
        except sqlite3.IntegrityError as e:
            QMessageBox.information(self, "Error", f"Error: {e}")
            conn.close()
            return False
        finally:
            conn.close()

        return True

# Password Manager Window for adding, viewing, and managing credentials
class PasswordManagerWindow(QWidget):
    def __init__(self, user_id):
        super().__init__()
        self.setWindowTitle(f'Password Manager')
        self.setWindowOpacity(0.9)
        set_dark_theme(self)

        icon_path = self.find_icon('ICON/icons8-app-50.png')

        if icon_path:
            self.setWindowIcon(QIcon(icon_path))
        else:
            self.setWindowIcon(QIcon('ICON/icons8-app-50.png'))

        self.user_id = user_id
        layout = QVBoxLayout()

        # UI setup for website input, username, and password
        self.website_input = QLineEdit(self)
        self.website_input.setPlaceholderText('Website')
        layout.addWidget(self.website_input)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText('Username')
        layout.addWidget(self.username_input)

        # Password field with hidden text by default
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('Password')
        self.password_input.setEchoMode(QLineEdit.Password)  # Hide the password by default
        layout.addWidget(self.password_input)

        # Add the action to toggle password visibility
        self.show_hide_password_action = QAction("Show Password", self)
        self.show_hide_password_action.triggered.connect(self.toggle_password_visibility)
        self.password_input.addAction(self.show_hide_password_action, QLineEdit.TrailingPosition)

        # Save button for storing credentials
        self.save_button = QPushButton('Save Credential', self)
        self.save_button.clicked.connect(self.save_credential)
        layout.addWidget(self.save_button)

        # Credentials table
        self.credentials_table = QTableWidget(self)
        self.credentials_table.setRowCount(0)
        self.credentials_table.setColumnCount(3)
        self.credentials_table.setHorizontalHeaderLabels(["Website", "Username", "Password"])
        self.credentials_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.credentials_table.cellClicked.connect(self.autofill_from_table)
        layout.addWidget(self.credentials_table)

        self.load_credentials()

        # Add Password Generator and Backup buttons
        self.gen_button = QPushButton("PassGuardX Generate", self)
        self.gen_button.clicked.connect(self.open_gen)
        layout.addWidget(self.gen_button)

        self.run_button = QPushButton("Backup", self)
        self.run_button.clicked.connect(self.run_exe)
        layout.addWidget(self.run_button)

        # Set up timeout timer (5 minutes of inactivity)
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.setInterval(5 * 60 * 1000)  # 5 minutes in milliseconds
        self.inactivity_timer.timeout.connect(self.close_window)
        self.inactivity_timer.start()

        self.setLayout(layout)

    def toggle_password_visibility(self):
        """Toggles between showing and hiding the password."""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_hide_password_action.setText("Hide Password")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_hide_password_action.setText("Show Password")


    def close_window(self):
        self.close()
        self.open_password_manager_app()

    def open_password_manager_app(self):
        self.PasswordManagerApp = PasswordManagerApp()  # Replace with your PasswordManagerApp class
        self.PasswordManagerApp.show()

    def reset_inactivity_timer(self):
        """Reset the inactivity timer when user interacts with the window."""
        self.inactivity_timer.start()

    def mouseMoveEvent(self, event):
        self.reset_inactivity_timer()

    def keyPressEvent(self, event):
        self.reset_inactivity_timer()

    def autofill_from_table(self, row, column):
        website = self.credentials_table.item(row, 0).text()
        username = self.credentials_table.item(row, 1).text()
        password = self.credentials_table.item(row, 2).text()

        # Fill in the fields with the selected data
        self.website_input.setText(website)
        self.username_input.setText(username)
        self.password_input.setText(password)

    def open_gen(self):
        self.Alpha_Pass = PasswordGeneratorApp()
        self.Alpha_Pass.show()

    def run_exe(self):
        self.backup = BackupApp()
        self.backup.show()
        
    def show_message(self, title, message, message_type):
        msg = QMessageBox()
        msg.setWindowTitle(title)
        msg.setText(message)

        if message_type == "info":
            msg.setIcon(QMessageBox.Information)
        elif message_type == "error":
            msg.setIcon(QMessageBox.Critical)

        icon_path = self.find_icon('ICON/icons8-app-50.png')
        if icon_path:
            msg.setWindowIcon(QIcon(icon_path))
        else:
            msg.setWindowIcon(QIcon('ICON/icons8-app-50.png'))

        msg.exec_()

    def find_icon(self, icon_name):
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

    def encrypt_data(self, data):
        """Encrypt the password before storing it."""
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = cipher.iv
        return (iv + ct_bytes).hex()  # Store as a hex string

    def decrypt_data(self, enc_data):
        """Decrypts the encrypted password."""
        # Ensure that the encrypted data is in bytes
        if isinstance(enc_data, str):
            enc_data = bytes.fromhex(enc_data)  # Convert hex string to bytes

        iv = enc_data[:16]  # First 16 bytes are the IV
        ct = enc_data[16:]  # The rest is the ciphertext

        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ct), AES.block_size)
        return decrypted_data.decode()

    def save_credential(self):
        website = self.website_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        # Encrypt password before storing
        encrypted_password = self.encrypt_data(password)

        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO credentials (website, username, password, user_id) VALUES (?, ?, ?, ?)",
                    (website, username, encrypted_password, self.user_id))
        conn.commit()
        conn.close()

        self.load_credentials()

    def load_credentials(self):
        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credentials WHERE user_id = ?", (self.user_id,))
        credentials = cursor.fetchall()
        conn.close()

        self.credentials_table.setRowCount(0)
        for row_num, (id, website, username, encrypted_password, user_id) in enumerate(credentials):
            self.credentials_table.insertRow(row_num)
            self.credentials_table.setItem(row_num, 0, QTableWidgetItem(website))
            self.credentials_table.setItem(row_num, 1, QTableWidgetItem(username))
            decrypted_password = self.decrypt_data(encrypted_password)
            self.credentials_table.setItem(row_num, 2, QTableWidgetItem(decrypted_password))

    def check_breach(self, email):
        headers = {'User-Agent': 'DarkWebMonitor/1.0'}
        try:
            response = requests.get(f"{HIBP_API_URL}/{email}", headers=headers)
            if response.status_code == 200:
                breaches = response.json()
                return breaches
            elif response.status_code == 404:
                return None  # No breach found
            else:
                logging.error(f"Failed to check breach for {email}, status code: {response.status_code}")
                return None
        except Exception as e:
            logging.error(f"Error while checking breach for {email}: {e}")
            return None

    def scan_for_breaches(self):
        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users")
        users = cursor.fetchall()

        for user in users:
            email = user[0]
            breaches = self.check_breach(email)
            if breaches:
                logging.info(f"Breaches found for {email}:")
                for breach in breaches:
                    logging.info(f"  - {breach['Name']} (Date: {breach['BreachDate']})")
            else:
                logging.info(f"No breaches found for {email}")
        conn.close()

def main():
    app = QApplication(sys.argv)
    window = PasswordManagerApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
