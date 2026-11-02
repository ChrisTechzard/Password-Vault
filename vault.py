import base64
import getpass #lets us enter passwords secretly
import json #helps us organize our credentials
import os #we are looking at being able to communicate with our system
import secrets #we get to generate secure random values
import string
from pathlib import Path #working with our vault file

from cryptography.fernet import Fernet, InvalidToken #encryption and decryption
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt #turns our master password into an encryption key

VAULT_FILE = Path("vault.json")
SALT_SIZE = 16


def derive_key(master_password, salt):
    """Derive an encryption key from the master password."""
    kdf = Scrypt( #here is where the security magic starts
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def save_vault(cipher, entries, salt):
    """Encrypt all entries before saving them to disk."""
    encrypted = cipher.encrypt(
        json.dumps(entries).encode("utf-8")
    )

    data = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": encrypted.decode("ascii"),
    }

    with VAULT_FILE.open("w", encoding="utf-8") as file:
        json.dump(data, file)

    os.chmod(VAULT_FILE, 0o600)


def load_vault(master_password):
    """Create a vault or unlock an existing one."""
    if not VAULT_FILE.exists():
        salt = secrets.token_bytes(SALT_SIZE)
        cipher = Fernet(derive_key(master_password, salt))
        save_vault(cipher, {}, salt)
        return cipher, {}, salt

    try:
        data = json.loads(VAULT_FILE.read_text(encoding="utf-8"))
        salt = base64.b64decode(data["salt"], validate=True)
        if len(salt) != SALT_SIZE:
            raise ValueError("Invalid salt")

        cipher = Fernet(derive_key(master_password, salt))
        decrypted = cipher.decrypt(data["data"].encode("ascii"))
        entries = json.loads(decrypted.decode("utf-8"))

        if not isinstance(entries, dict):
            raise ValueError("Invalid vault contents")

        return cipher, entries, salt

    except InvalidToken:
        raise ValueError("Wrong master password or damaged vault.")
    except (ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError) as error:
        raise ValueError("Vault file is invalid or damaged.") from error


def add_password(entries):
    site = input("Website or service: ").strip()
    username = input("Username or email: ").strip()
    password = getpass.getpass("Password to store: ")

    if not site or not username or not password:
        print("All fields are required.")
        return

    entries[site] = {
        "username": username,
        "password": password,
    }
    print("Credential added!")


def list_sites(entries):
    if not entries:
        print("Your vault is empty.")
        return

    print("\nSaved services:")
    for site in sorted(entries):
        print(f"- {site}")


def get_password(entries):
    site = input("Which service? ").strip()

    if site not in entries:
        print("No entry found.")
        return

    entry = entries[site]
    print("Username:", entry["username"])
    print("Password:", entry["password"])


def delete_password(entries):
    site = input("Service to delete: ").strip()

    if site not in entries:
        print("No entry found.")
        return

    confirm = input(f"Delete {site}? Type YES to confirm: ")
    if confirm == "YES":
        del entries[site]
        print("Entry deleted.")


def main():
    print("=== CHRIS TECHZARD: PYTHON VAULT ===")

    if not VAULT_FILE.exists():
        master = getpass.getpass("Create a master password: ")
        if len(master) < 12:
            print("Use at least 12 characters. Try again.")
            return
        confirm = getpass.getpass("Confirm master password: ")
        if master != confirm:
            print("Passwords do not match.")
            return
    else:
        master = getpass.getpass("Master password: ")

    try:
        cipher, entries, salt = load_vault(master)
    except ValueError as error:
        print(error)
        return

    print("Vault unlocked!")

    while True:
        print("""
1. Add credential
2. List saved services
3. Retrieve credential
4. Delete credential
5. Generate a password
6. Lock and exit
""")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            add_password(entries)
            save_vault(cipher, entries, salt)

        elif choice == "2":
            list_sites(entries)

        elif choice == "3":
            get_password(entries)

        elif choice == "4":
            delete_password(entries)
            save_vault(cipher, entries, salt)

        elif choice == "5":
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            password = "".join(
                secrets.choice(alphabet) for _ in range(20)
            )
            print("Generated password:", password)

        elif choice == "6":
            print("Vault locked. Goodbye!")
            break

        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()
