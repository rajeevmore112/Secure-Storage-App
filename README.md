# Secure-Storage-App
A secure file storage system built with Python, featuring AES-256-GCM encryption, PBKDF2 password-based key derivation, optional secure wipe, and a modern Tkinter GUI. Provides safe encryption, decryption, password strength checks, file logs, and multi-threaded execution.

## Features

### Strong Encryption
- AES-256-GCM (authenticated encryption)
- PBKDF2-HMAC-SHA256 key derivation (200,000 iterations)
- Per-file random salt + nonce
- Protects confidentiality and detects tampering

### Password Security
- Password strength indicator
- Password show/hide toggle
- One-click strong password generator

### Modern Tkinter GUI
- File browser
- Log window (real-time updates)
- File lists for encrypted & decrypted files
- Progress bar for long operations
- Responsive (threaded encryption/decryption)

### Secure Data Handling
- Optional: Remove original after encrypt/decrypt
- Optional: Secure wipe (3-pass overwrite)
- Automatic folder creation
- Timestamped logging (ISO-8601)

### Distribution-Ready
- Fully compatible with PyInstaller
- Works standalone as a Windows EXE
- Safe folder structure for storing encrypted/decrypted files

## Installation
1. Clone the repository
- git clone https://github.com/<your-username>/Secure-File-Storage-System.git
- cd Secure-File-Storage-System

2. Create virtual environment (recommended)
- python -m venv venv
- venv\Scripts\activate     # Windows

4. Install dependencies
- pip install -r requirements.txt

## Running the Application
GUI Version
- python secure_storage_gui_v2.py

CLI Version
- python secure_storage_pw.py

