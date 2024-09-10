# This code has been written for the Secret Notes assignment in the Python Bootcamp by Atil Samancioglu
# Author: Cosku Inceler
# Date: 10.09.2024
import tkinter as tk
from tkinter import messagebox
from PIL import ImageTk, Image
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# GUI Properties
SNWindow = tk.Tk()
SNWindow.minsize(width = 400, height = 700)
SNWindow.title("Secret Notes")
SNWindow.iconbitmap(r"Logo.ico")
SNWindow.config(padx=30, pady=20)
LogoImage = Image.open("Logo.png")
LogoImage = LogoImage.resize((200, 200), Image.LANCZOS)
LabelImage = ImageTk.PhotoImage(LogoImage)
LogoLabel = tk.Label(image = LabelImage, pady = 20)
LogoLabel.pack()

# Widget Properties
TitleLabel = tk.Label(text = "Please enter you title", font = ("Arial", 16, "normal"))
TitleLabel.pack()
TitleEntry = tk.Entry(font = ("Arial", 12, "normal"))
TitleEntry.pack()
NoteLabel = tk.Label(text = "Please enter your note", font = ("Arial", 16, "normal"), pady = 10)
NoteLabel.pack()
NoteText = tk.Text(width = 30, height = 10, font = ("Arial", 12, "normal"))
NoteText.pack()
def EncryptedTextCreator():
    if TitleEntry.get() == "" or NoteText.get("1.0", "end") == "" or PasswordEntry.get() == "":
        tk.messagebox.showerror("Error", "Please enter a valid argument in every space")
    else:
        NoteFile = open("SecretNotes.txt", "a")
        NoteFile.write(TitleEntry.get() + "\n" + str(Encrypted) + "\n")
        NoteFile.close()
        tk.messagebox.showinfo("Save", message="Your text has been saved")
        TitleEntry.delete(0, "end")
        NoteText.delete("1.0", "end")
        PasswordEntry.delete(0, "end")
def DecryptText():
    if NoteText.get("1.0", "end") == "" or PasswordEntry.get() == "":
        tk.messagebox.showerror("Error", "Please enter the text to be decrypted and the correct password")
    else:
        NoteText.insert("1.0", DecryptedText)
PasswordLabel = tk.Label(text = "Please enter you password", font = ("Arial", 16, "normal"), pady = 10)
PasswordLabel.pack()
PasswordEntry = tk.Entry(font = ("Arial", 12, "normal"))
PasswordEntry.pack()
SaveAndEncryptButton = tk.Button(text = "Encrypt & Save", pady = 10, command = EncryptedTextCreator)
SaveAndEncryptButton.pack()
DecryptButton = tk.Button(text = "Decrypt", pady = 10, command = DecryptText)
DecryptButton.pack()

# Encryption Functionality
password = str.encode(PasswordEntry.get())
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)
Key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(Key)
Original = NoteText.get("1.0", "end")
Encrypted = f.encrypt(str.encode(Original))
# Decryption Functionality
Text2Decrypt = NoteText.get("1.0", "end")
DecryptedText = f.decrypt(Encrypted)

# Main Loop
SNWindow.mainloop()