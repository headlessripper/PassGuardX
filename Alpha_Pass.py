import sys
import random
import string
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QCheckBox, QVBoxLayout, QWidget, QMessageBox, QHBoxLayout
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import Qt

class PasswordGeneratorApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PassGuardX")
        self.setGeometry(100, 100, 600, 450)
        self.setWindowOpacity(0.9)

        icon_path = self.find_icon('ICON/icons8-app-50.png')
        
        # Check if the icon file exists, and set it accordingly
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))
        else:
            self.setWindowIcon(QIcon('background/icon.png'))  # Fallback icon
            QMessageBox.critical(self, "Error", f"Icon file not found: {icon_path}. Make sure the path is correct.")

        # Path to the icon you want to use
        background_path = self.find_bg_icon('background/background.jpeg')            

        # Set background image
        if os.path.exists(background_path):
            formatted_background_path = background_path.replace('\\', '/')
            self.setStyleSheet(f"""
                QWidget {{
                    background-image: url({formatted_background_path});
                    background-color: #2E2E2E;
                }}
            """)
        else:
            QMessageBox.critical(self, "Error", f"Background image not found: {background_path}. Make sure the path is correct.")

        # Main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)

        self.create_widgets()

    def find_bg_icon(self, icon_name):
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

    def create_widgets(self):   
        # Title label
        self.title_label = QLabel("PassGuardX Generate")
        self.title_label.setFont(QFont('Segoe UI', 24, QFont.Weight.Bold))
        self.title_label.setStyleSheet("color: #F0F0F0;")
        self.layout.addWidget(self.title_label)

        # Length entry
        self.length_label = QLabel("Password Length (minimum 8):")
        self.length_label.setFont(QFont('Segoe UI', 14))
        self.length_label.setStyleSheet("color: #F0F0F0;")
        self.layout.addWidget(self.length_label)

        self.length_entry = QLineEdit()
        self.length_entry.setPlaceholderText("8")
        self.length_entry.setStyleSheet(""" 
            padding: 10px; 
            font-size: 16px; 
            border: 1px solid #555; 
            border-radius: 5px; 
            background-color: #333; 
            color: #F0F0F0;
        """)
        self.layout.addWidget(self.length_entry)

        # Checkbox options
        self.checkboxes_layout = QVBoxLayout()
        self.checkboxes_layout.setSpacing(10)

        self.uppercase_checkbox = QCheckBox("Include uppercase letters")
        self.uppercase_checkbox.setChecked(True)
        self.uppercase_checkbox.setStyleSheet("color: #F0F0F0;")
        self.checkboxes_layout.addWidget(self.uppercase_checkbox)

        self.lowercase_checkbox = QCheckBox("Include lowercase letters")
        self.lowercase_checkbox.setChecked(True)
        self.lowercase_checkbox.setStyleSheet("color: #F0F0F0;")
        self.checkboxes_layout.addWidget(self.lowercase_checkbox)

        self.digits_checkbox = QCheckBox("Include digits")
        self.digits_checkbox.setChecked(True)
        self.digits_checkbox.setStyleSheet("color: #F0F0F0;")
        self.checkboxes_layout.addWidget(self.digits_checkbox)

        self.special_checkbox = QCheckBox("Include special characters")
        self.special_checkbox.setChecked(True)
        self.special_checkbox.setStyleSheet("color: #F0F0F0;")
        self.checkboxes_layout.addWidget(self.special_checkbox)

        self.layout.addLayout(self.checkboxes_layout)

        # Button layout
        self.button_layout = QHBoxLayout()
        self.button_layout.setSpacing(15)

        # Generate button
        self.generate_button = QPushButton("Generate Password")
        self.generate_button.clicked.connect(self.generate_password)
        self.generate_button.setStyleSheet("""
            background-color: #007BFF;
            color: #FFFFFF;
            border: none;
            border-radius: 5px;
            padding: 12px;
            font-size: 16px;
        """)
        self.generate_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.button_layout.addWidget(self.generate_button)

        # Copy button
        self.copy_button = QPushButton("Copy to Clipboard")
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        self.copy_button.setStyleSheet("""
            background-color: #28A745;
            color: #FFFFFF;
            border: none;
            border-radius: 5px;
            padding: 12px;
            font-size: 16px;
        """)
        self.copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.button_layout.addWidget(self.copy_button)

        self.layout.addLayout(self.button_layout)

        # Result label
        self.result_label = QLabel("")
        self.result_label.setFont(QFont('Segoe UI', 14))
        self.result_label.setStyleSheet("""
            color: #F0F0F0;
            border: 1px solid #555;
            padding: 15px;
            background-color: #333;
            border-radius: 5px;
        """)
        self.layout.addWidget(self.result_label)

    def generate_password(self):
        try:
            length = int(self.length_entry.text())
            if length < 8:
                raise ValueError("Password length should be at least 8 characters")

            upper = string.ascii_uppercase if self.uppercase_checkbox.isChecked() else ""
            lower = string.ascii_lowercase if self.lowercase_checkbox.isChecked() else ""
            digits = string.digits if self.digits_checkbox.isChecked() else ""
            special = string.punctuation if self.special_checkbox.isChecked() else ""

            if not (upper or lower or digits or special):
                raise ValueError("At least one character set must be enabled")

            all_characters = upper + lower + digits + special
            password = [random.choice(char_set) for char_set in [upper, lower, digits, special] if char_set]
            password += random.choices(all_characters, k=max(length - len(password), 0))
            random.shuffle(password)
            password_str = ''.join(password)

            self.result_label.setText(password_str)

        except ValueError as e:
            QMessageBox.critical(self, "Error", str(e))

    def copy_to_clipboard(self):
        password = self.result_label.text()
        if password:
            clipboard = QApplication.clipboard()
            clipboard.setText(password)
            QMessageBox.information(self, "Success", "Password copied to clipboard!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordGeneratorApp()
    window.show()
    sys.exit(app.exec())
