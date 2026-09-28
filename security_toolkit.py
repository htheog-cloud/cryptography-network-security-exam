#!/usr/bin/env python3
"""
ULK Polytechnic Institute - Security Toolkit
Module: Cryptography & Network Security (ETTCS801)

Description:
A command-line utility providing AES symmetric encryption/decryption 
(via Fernet) and SHA-256 integrity verification with error handling.
"""

import sys
import os
import argparse
import hashlib
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"

def generate_or_load_key():
    """Generates a new Fernet key or loads an existing key from file."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as kf:
            kf.write(key)
        print(f"[+] New key generated and saved to '{KEY_FILE}'.")
    else:
        with open(KEY_FILE, "rb") as kf:
            key = kf.read()
    return key

def calculate_sha256(file_path):
    """Calculates and returns the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"[!] Error: File '{file_path}' was not found.")
        sys.exit(1)

def encrypt_file(file_path):
    """Encrypts a plaintext file using AES (Fernet)."""
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' does not exist.")
        sys.exit(1)

    key = generate_or_load_key()
    fernet = Fernet(key)

    original_hash = calculate_sha256(file_path)
    print(f"[+] Original SHA-256 Hash: {original_hash}")

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)
    out_file = file_path + ".enc"

    with open(out_file, "wb") as f:
        f.write(encrypted_data)

    print(f"[+] File encrypted successfully. Output saved to: '{out_file}'")

def decrypt_file(file_path):
    """Decrypts an encrypted (.enc) file using AES (Fernet)."""
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' does not exist.")
        sys.exit(1)

    key = generate_or_load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        print(f"[!] Decryption failed: Invalid key or corrupted payload. ({e})")
        sys.exit(1)

    out_file = file_path.replace(".enc", "")
    if out_file == file_path:
        out_file = "decrypted_" + file_path

    with open(out_file, "wb") as f:
        f.write(decrypted_data)

    decrypted_hash = calculate_sha256(out_file)
    print(f"[+] File decrypted successfully. Output saved to: '{out_file}'")
    print(f"[+] Decrypted File SHA-256 Hash: {decrypted_hash}")

def verify_file(file_path, expected_hash):
    """Verifies file integrity by comparing current SHA-256 to expected hash."""
    current_hash = calculate_sha256(file_path)
    print(f"[+] Current SHA-256 Hash: {current_hash}")
    print(f"[+] Expected SHA-256 Hash: {expected_hash}")

    if current_hash.lower() == expected_hash.lower():
        print("[+] INTEGRITY VERIFICATION: PASSED (File matches original!)")
    else:
        print("[!] INTEGRITY VERIFICATION: FAILED (File has been altered or tampered with!)")

def main():
    parser = argparse.ArgumentParser(description="ULK Security Toolkit - Encryption & Integrity Verification")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", "-e", metavar="FILE", help="Encrypt a target file")
    group.add_argument("--decrypt", "-d", metavar="FILE", help="Decrypt a target file")
    group.add_argument("--hash", "-H", metavar="FILE", help="Calculate SHA-256 hash of a file")
    group.add_argument("--verify", "-v", nargs=2, metavar=("FILE", "HASH"), help="Verify file hash integrity")

    args = parser.parse_args()

    if args.encrypt:
        encrypt_file(args.encrypt)
    elif args.decrypt:
        decrypt_file(args.decrypt)
    elif args.hash:
        h = calculate_sha256(args.hash)
        print(f"[+] File SHA-256: {h}")
    elif args.verify:
        verify_file(args.verify[0], args.verify[1])

if __name__ == "__main__":
    main()
