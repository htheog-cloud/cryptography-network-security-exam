from cryptography.fernet import Fernet, InvalidToken
import hashlib
import os
import sys


def generate_key(key_file):
    """Generate an encryption key if one does not already exist."""
    if not os.path.exists(key_file):
        key = Fernet.generate_key()

        with open(key_file, "wb") as file:
            file.write(key)

        print("Encryption key generated.")
    else:
        print("Existing encryption key found.")


def load_key(key_file):
    """Load and validate the encryption key."""
    try:
        with open(key_file, "rb") as file:
            key = file.read()

        Fernet(key)
        return key

    except FileNotFoundError:
        print("Error: Encryption key file was not found.")
        return None

    except ValueError:
        print("Error: Invalid encryption key.")
        return None


def calculate_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except FileNotFoundError:
        print(f"Error: File '{file_path}' was not found.")
        return None


def encrypt_file(input_file, encrypted_file, key):
    """Encrypt the supplied file."""
    try:
        with open(input_file, "rb") as file:
            original_data = file.read()

        encrypted_data = Fernet(key).encrypt(original_data)

        with open(encrypted_file, "wb") as file:
            file.write(encrypted_data)

        print(f"File encrypted successfully: {encrypted_file}")

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' was not found.")

    except PermissionError:
        print("Error: Permission denied while accessing the file.")


def decrypt_file(encrypted_file, decrypted_file, key):
    """Decrypt the encrypted file."""
    try:
        with open(encrypted_file, "rb") as file:
            encrypted_data = file.read()

        decrypted_data = Fernet(key).decrypt(encrypted_data)

        with open(decrypted_file, "wb") as file:
            file.write(decrypted_data)

        print(f"File decrypted successfully: {decrypted_file}")

    except FileNotFoundError:
        print(f"Error: Encrypted file '{encrypted_file}' was not found.")

    except InvalidToken:
        print("Error: Decryption failed. The file may have been changed or the key is invalid.")

    except PermissionError:
        print("Error: Permission denied while accessing the file.")


def verify_contents(original_file, decrypted_file):
    """Verify that the decrypted file matches the original."""
    try:
        with open(original_file, "rb") as file:
            original_data = file.read()

        with open(decrypted_file, "rb") as file:
            decrypted_data = file.read()

        if original_data == decrypted_data:
            print("Verification successful: Decrypted contents match the original.")
            return True
        else:
            print("Verification failed: Decrypted contents do not match the original.")
            return False

    except FileNotFoundError:
        print("Error: Original or decrypted file was not found.")
        return False


def check_file_integrity(file_path, original_hash):
    """Compare the current SHA-256 hash with the original hash."""
    current_hash = calculate_hash(file_path)

    if current_hash is None:
        return False

    print("Original SHA-256:", original_hash)
    print("Current SHA-256: ", current_hash)

    if current_hash == original_hash:
        print("Integrity check: PASSED - File has not changed.")
        return True
    else:
        print("Integrity check: FAILED - File has been changed.")
        return False


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("python encryption_tool.py <student_record_file>")
        return

    input_file = sys.argv[1]

    if not os.path.isfile(input_file):
        print(f"Error: '{input_file}' does not exist.")
        return

    # Keep the key outside the GitHub repository.
    key_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "student_encryption.key")

    encrypted_file = input_file + ".encrypted"
    decrypted_file = input_file + ".decrypted"

    # Generate key if necessary and load it.
    generate_key(key_file)

    key = load_key(key_file)

    if key is None:
        return

    # Calculate original SHA-256 hash.
    original_hash = calculate_hash(input_file)

    if original_hash is None:
        return

    print("\nOriginal SHA-256 hash:")
    print(original_hash)

    # Encrypt.
    encrypt_file(input_file, encrypted_file, key)

    # Decrypt.
    decrypt_file(encrypted_file, decrypted_file, key)

    # Verify decrypted contents.
    verify_contents(input_file, decrypted_file)

    # Check integrity.
    print("\nChecking file integrity:")
    check_file_integrity(input_file, original_hash)


if __name__ == "__main__":
    main()