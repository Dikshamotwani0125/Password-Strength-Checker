# Password Manager

A simple and secure password manager built using Python and the `cryptography` library. This tool allows you to securely store and retrieve passwords using encryption.

## Features
- **Add Password**: Encrypt and save a new password securely.
- **Retrieve Password**: Decrypt and retrieve stored passwords using your master password.

## Prerequisites
Make sure you have Python installed on your system. You also need to install the `cryptography` library.

```bash
pip install cryptography
```

## How It Works
1. Passwords are encrypted using the `cryptography.fernet` module.
2. A key is derived from a master password using the PBKDF2 algorithm with a SHA256 hash.
3. Encrypted credentials are stored in a file named `credentials.enc`.
4. You can securely retrieve these credentials using your master password.

## Usage

### 1. Clone the Repository
Clone this repository to your local machine.
```bash
git clone <repository_url>
cd <repository_directory>
```

### 2. Run the Script
The script supports two main actions: `add` and `get`.

#### Add a New Password
To add a new password, run:
```bash
python password_manager.py add
```
You will be prompted to enter a new password, which will be securely encrypted and saved.

#### Retrieve a Saved Password
To retrieve a saved password, run:
```bash
python password_manager.py get
```
You will be prompted to enter your master password to decrypt and retrieve the saved password.

## Code
```python
import sys
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt',
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def load_credentials(key):
    try:
        with open('credentials.enc', 'rb') as f:
            encrypted_data = f.read()
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data)
    except (IOError, OSError, FernetError):
        return None

def save_credentials(key, credentials):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(credentials)
    with open('credentials.enc', 'wb') as f:
        f.write(encrypted_data)

def main():
    if len(sys.argv) != 2:
        print("Usage: python password_manager.py [add|get]")
        return

    action = sys.argv[1]

    if action == 'add':
        password = getpass.getpass("Enter a new password: ")
        key = generate_key(password.encode())
        save_credentials(key, password.encode())
        print("Password saved.")

    elif action == 'get':
        password = getpass.getpass("Enter your password: ")
        key = generate_key(password.encode())
        loaded_credentials = load_credentials(key)

        if loaded_credentials is None:
            print("No saved credentials found.")
        else:
            print("Retrieved password:", loaded_credentials.decode())

    else:
        print("Invalid action. Use 'add' or 'get'.")

if __name__ == '__main__':
    main()
```

## Notes
- The script uses a static salt (`b'salt'`). For production, consider using a unique salt for each password and storing it securely.
- Keep your master password secure; losing it will make retrieving your saved passwords impossible.

## License
This project is licensed under the MIT License. Feel free to use and modify it as needed.

## Author
[Your Name](https://github.com/your_github_profile)

---
Feel free to open issues or submit pull requests to improve the functionality of this password manager!

