"""
Software Security (SDEV 4303) - Assignment 3
Chapter 03: User Authentication - Programming Task
Password Hashing and Salting Authentication System

Language: Python 3
Algorithm: SHA-256 (Secure Hash Algorithm)
Storage: Plaintext structured file (users_database.txt)
"""

import hashlib
import os
import secrets

DB_FILE = "users_database.txt"


def hash_password(password: str, salt: str) -> str:
    """
    Concatenates password and salt, then computes SHA-256 hash.
    Format: SHA-256(password + salt)
    """
    combined = password.encode('utf-8') + salt.encode('utf-8')
    return hashlib.sha256(combined).hexdigest()


def register_user(username: str, password: str) -> bool:
    """
    Registers a new user by generating a random salt,
    hashing the concatenated password and salt, and storing the record.
    """
    username = username.strip()
    if not username or not password:
        print("[ERROR] Username and password cannot be empty.")
        return False

    # Check if database file exists and if user already registered
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) == 3 and parts[0].lower() == username.lower():
                    print(f"[ERROR] User '{username}' is already registered!")
                    return False

    # Generate a cryptographically secure random 16-byte (32-hex-character) salt
    salt = secrets.token_hex(16)
    hashed_pwd = hash_password(password, salt)

    # Append the new record: username:salt:hashed_password
    with open(DB_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username}:{salt}:{hashed_pwd}\n")

    print(f"[SUCCESS] User '{username}' registered successfully.")
    print(f"          Generated Salt (Hex): {salt}")
    print(f"          Computed SHA-256 Hash: {hashed_pwd}")
    return True


def login_user(username: str, password: str) -> bool:
    """
    Authenticates a user by retrieving their salt, hashing the candidate
    password with that salt, and comparing it against the stored hash.
    """
    username = username.strip()
    if not os.path.exists(DB_FILE):
        print("[ERROR] User database does not exist. Please register first.")
        return False

    with open(DB_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) == 3:
                stored_user, stored_salt, stored_hash = parts
                if stored_user.lower() == username.lower():
                    # Recompute hash with candidate password and stored salt
                    computed_hash = hash_password(password, stored_salt)
                    if computed_hash == stored_hash:
                        print(f"[SUCCESS] Authentication successful! Welcome, {stored_user}.")
                        return True
                    else:
                        print("[FAILED] Authentication failed: Incorrect password.")
                        return False

    print(f"[FAILED] Authentication failed: User '{username}' not found.")
    return False


def run_demonstration():
    """Automated demonstration showing registration, file content, and login scenarios."""
    print("=" * 65)
    print("   SOFTWARE SECURITY (SDEV 4303) - PASSWORD HASHING DEMO")
    print("=" * 65)

    # Reset test database for clean demonstration
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    print("\n[+] Initialized clean database: users_database.txt\n")

    # 1. Registration Phase
    print("-" * 50)
    print("1. USER REGISTRATION PHASE")
    print("-" * 50)
    register_user("abdelkareem", "Secur!ty2026")
    print()
    register_user("alice", "MySecretPass#1")
    print()
    register_user("bob", "P@ssw0rd99")
    print()
    # Attempt duplicate registration
    print("[*] Testing duplicate registration prevention:")
    register_user("alice", "AnotherPassword")

    # 2. Database Content Inspection
    print("\n" + "-" * 50)
    print("2. DATABASE FILE CONTENTS (users_database.txt)")
    print("-" * 50)
    with open(DB_FILE, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            u, s, h = line.strip().split(":")
            print(f"Record {i}:")
            print(f"  User: {u}")
            print(f"  Salt: {s}")
            print(f"  Hash: {h}\n")

    # 3. Authentication / Login Phase
    print("-" * 50)
    print("3. AUTHENTICATION & LOGIN TESTING")
    print("-" * 50)

    print("\nTest Case 1: Valid credentials for 'abdelkareem'")
    login_user("abdelkareem", "Secur!ty2026")

    print("\nTest Case 2: Incorrect password for 'alice'")
    login_user("alice", "WrongPass123")

    print("\nTest Case 3: Non-existent user")
    login_user("charlie", "password")

    print("\nTest Case 4: Valid credentials for 'alice'")
    login_user("alice", "MySecretPass#1")

    print("\n" + "=" * 65)
    print("   DEMONSTRATION COMPLETE - ALL SECURITY CONTROLS VERIFIED")
    print("=" * 65)


if __name__ == "__main__":
    run_demonstration()
