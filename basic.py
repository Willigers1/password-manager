import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants for file names
KEY_FILE = "key.key"
SALT_FILE = "salt.salt"
PASSWORD_FILE = "passwords.json"

# Function to derive key from master password
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a secret key from the master password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to initialize key and salt
def initialize_key():
    """Initialize the encryption key and salt."""
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as salt_file:
        salt_file.write(salt)
    while True:
        master_pwd = input("Create a master password: ")
        confirm_pwd = input("Confirm your master password: ")
        if master_pwd != confirm_pwd:
            print("Passwords do not match. Please try again.")
            continue
        if not master_pwd:
            print("Master password cannot be empty. Please try again.")
            continue
        break
    key = derive_key(master_pwd, salt)
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print("Master password set and key generated.")
    return key

# Function to load existing key
def load_existing_key():
    """Load the existing encryption key using the master password."""
    if not os.path.exists(SALT_FILE):
        print("Salt file missing. Cannot derive key.")
        exit()
    with open(SALT_FILE, "rb") as salt_file:
        salt = salt_file.read()
    master_pwd = input("Enter your master password: ")
    key = derive_key(master_pwd, salt)
    if not os.path.exists(KEY_FILE):
        print("Key file missing. Cannot verify master password.")
        exit()
    with open(KEY_FILE, "rb") as key_file:
        stored_key = key_file.read()
    if key != stored_key:
        print("Invalid master password!")
        exit()
    print("Master password verified.")
    return key

# Function to initialize or load the encryption key
def get_fernet():
    """Retrieve the Fernet object for encryption/decryption."""
    if not os.path.exists(KEY_FILE) or not os.path.exists(SALT_FILE):
        key = initialize_key()
    else:
        key = load_existing_key()
    return Fernet(key)

# Function to add a new password
def add_password(fernet):
    """Add a new account and its password."""
    while True:
        account = input("Account name: ").strip()
        if not account:
            print("Account name cannot be empty. Please try again.")
            continue
        break

    while True:
        pwd = input("Password: ").strip()
        if not pwd:
            print("Password cannot be empty. Please try again.")
            continue
        break

    # Encrypt the password
    encrypted_pwd = fernet.encrypt(pwd.encode()).decode()

    # Load existing data
    data = []
    if os.path.exists(PASSWORD_FILE):
        try:
            with open(PASSWORD_FILE, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            print("Error reading the passwords file. It may be corrupted.")
            return

    # Append the new entry
    entry = {"account": account, "password": encrypted_pwd}
    data.append(entry)

    # Save back to the file
    try:
        with open(PASSWORD_FILE, "w") as f:
            json.dump(data, f, indent=4)
        print(f"Password for '{account}' added successfully.")
    except Exception as e:
        print(f"Failed to save password: {e}")

# Function to view stored passwords
def view_passwords(fernet):
    """View all stored accounts and their decrypted passwords."""
    if not os.path.exists(PASSWORD_FILE):
        print("No passwords stored yet.")
        return

    try:
        with open(PASSWORD_FILE, "r") as f:
            data = json.load(f)
            if not data:
                print("No passwords stored yet.")
                return
            for idx, entry in enumerate(data, start=1):
                account = entry.get("account")
                encrypted_pwd = entry.get("password")
                try:
                    decrypted_pwd = fernet.decrypt(encrypted_pwd.encode()).decode()
                except Exception as e:
                    decrypted_pwd = "Decryption Failed"
                    print(f"Error decrypting password for '{account}': {e}")
                print(f"{idx}. Account: {account} | Password: {decrypted_pwd}")
    except json.JSONDecodeError:
        print("Error reading the passwords file. It may be corrupted.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Function to delete a password entry
def delete_password(fernet):
    """Delete a password entry by its index."""
    if not os.path.exists(PASSWORD_FILE):
        print("No passwords stored yet.")
        return

    try:
        with open(PASSWORD_FILE, "r") as f:
            data = json.load(f)
            if not data:
                print("No passwords stored yet.")
                return
    except json.JSONDecodeError:
        print("Error reading the passwords file. It may be corrupted.")
        return

    # Display entries
    for idx, entry in enumerate(data, start=1):
        print(f"{idx}. {entry.get('account')}")

    while True:
        try:
            choice = int(input("Enter the number of the account to delete (0 to cancel): "))
            if choice == 0:
                print("Deletion canceled.")
                return
            if 1 <= choice <= len(data):
                removed = data.pop(choice - 1)
                with open(PASSWORD_FILE, "w") as f:
                    json.dump(data, f, indent=4)
                print(f"Deleted password for '{removed.get('account')}'.")
                return
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Please enter a valid number.")

# Function to update an existing password
def update_password(fernet):
    """Update the password for an existing account."""
    if not os.path.exists(PASSWORD_FILE):
        print("No passwords stored yet.")
        return

    try:
        with open(PASSWORD_FILE, "r") as f:
            data = json.load(f)
            if not data:
                print("No passwords stored yet.")
                return
    except json.JSONDecodeError:
        print("Error reading the passwords file. It may be corrupted.")
        return

    # Display entries
    for idx, entry in enumerate(data, start=1):
        print(f"{idx}. {entry.get('account')}")

    while True:
        try:
            choice = int(input("Enter the number of the account to update (0 to cancel): "))
            if choice == 0:
                print("Update canceled.")
                return
            if 1 <= choice <= len(data):
                account = data[choice - 1].get("account")
                break
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Please enter a valid number.")

    while True:
        new_pwd = input(f"Enter the new password for '{account}': ").strip()
        if not new_pwd:
            print("Password cannot be empty. Please try again.")
            continue
        break

    # Encrypt the new password
    encrypted_pwd = fernet.encrypt(new_pwd.encode()).decode()
    data[choice - 1]["password"] = encrypted_pwd

    # Save back to the file
    try:
        with open(PASSWORD_FILE, "w") as f:
            json.dump(data, f, indent=4)
        print(f"Password for '{account}' updated successfully.")
    except Exception as e:
        print(f"Failed to update password: {e}")

# Main function to handle user input
def main():
    """Main loop for the password manager."""
    fernet = get_fernet()

    while True:
        print("\n--- Password Manager ---")
        print("1. View passwords (view)")
        print("2. Add a new password (add)")
        print("3. Delete a password (delete)")
        print("4. Update a password (update)")
        print("5. Quit (q)")
        mode = input("Choose an option: ").strip().lower()

        if mode in ["q", "quit", "5"]:
            print("Exiting Password Manager. Goodbye!")
            break
        elif mode in ["view", "1"]:
            view_passwords(fernet)
        elif mode in ["add", "2"]:
            add_password(fernet)
        elif mode in ["delete", "3"]:
            delete_password(fernet)
        elif mode in ["update", "4"]:
            update_password(fernet)
        else:
            print("Invalid option. Please choose a valid action.")

if __name__ == "__main__":
    main()
