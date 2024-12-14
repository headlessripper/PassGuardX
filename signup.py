# Sign Up Page with Email Verification
class SignUpPage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Sign Up')
        self.setWindowOpacity(0.9)
        set_dark_theme(self)

        icon_path = self.find_icon('ICON/icons8-app-50.png')  # Try to find the icon

        # Set the icon if it's found, otherwise use a fallback
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

    def sign_up(self):
        username = self.username_input.text()
        email = self.email_input.text()
        password = self.password_input.text()
        
        # Generate a unique 6-digit verification code
        verification_code = random.randint(100000, 999999)
        
        # Send the verification email
        try:
            send_verification_email(email, verification_code)
            QMessageBox.information(self, "Verification", f"Verification code sent to {email}")
        except Exception as e:
            QMessageBox.information(self, "Email sending error",f"Error sending email: {e}")
            return
        
        # Prompt user for the code
        entered_code, ok = QInputDialog.getText(self, 'Verification', 'Enter the verification code sent to your email:')
        
        if ok and str(entered_code) == str(verification_code):
            QMessageBox.information(self, "Authentication Success","Verification successful!")
            # Proceed with registration
            self.register_user(username, email, password)
        else:
            QMessageBox.information(self, "Invalid verification code","Invalid verification code.")
    
    def register_user(self, username, email, password):
        # Connect to the database
        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        
        # Check if the email already exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            QMessageBox.information(self, "Attention!","Email is already registered. Please choose a different email.")
            conn.close()
            return False
        
        # Hash the password before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insert the new user into the database
        try:
            cursor.execute("INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)", 
                        (username, email, hashed_password))
            conn.commit()
            QMessageBox.information(self, "Success","User registered successfully!")
        except sqlite3.IntegrityError as e:
            QMessageBox.information(self, "Error",f"Error: {e}")
            conn.close()
            return False
        finally:
            conn.close()

        return True