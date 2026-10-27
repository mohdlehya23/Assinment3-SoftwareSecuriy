# Assignment 3: Software Security - User Authentication
**Islamic University of Gaza**  
**Faculty of Information Technology**  
**Course:** Software Security (SDEV 4303)  
**Instructor:** Dr. Abdelkareem Alashqar  
**Chapter 03:** User Authentication  

---

## 📌 Project Overview
This project implements a secure password hashing and salting authentication system using Python 3, SHA-256 (`hashlib`), and cryptographically secure pseudorandom number generators (`secrets`).

### Features:
1. **User Registration:**
   - Enforces unique usernames.
   - Generates a unique 16-byte (32-character hexadecimal) random salt using `secrets.token_hex(16)`.
   - Concatenates `password + salt` and computes the cryptographic SHA-256 hash.
   - Appends records to a persistent text database (`users_database.txt`) in `username:salt:hash` format.
2. **User Authentication & Login:**
   - Retrieves the specific salt for the user.
   - Re-computes the hash using the candidate password and retrieved salt.
   - Verifies the candidate hash against the stored hash.
   - Prevents duplicate registrations and protects against rainbow table lookups.

---

## 🚀 How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/mohdlehya23/Assinment3-SoftwareSecuriy.git
   cd Assinment3-SoftwareSecuriy
   ```

2. Execute the authentication program:
   ```bash
   python password_auth.py
   ```

3. Check the created database:
   ```bash
   cat users_database.txt
   ```
