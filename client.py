import requests
from tkinter import Tk, Label, Button, Entry, StringVar
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Clé AES partagée (doit être identique au serveur)
AES_KEY = os.urandom(32)

def encrypt_message(message):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB())
    encryptor = cipher.encryptor()
    padded_message = message.ljust(32).encode('utf-8')  # Pad à 32 octets
    return encryptor.update(padded_message) + encryptor.finalize()

def send_message():
    message = message_var.get()
    encrypted_message = encrypt_message(message)
    try:
        response = requests.post("http://localhost:5000/send_message", data=encrypted_message)
        status_label.config(text="Message envoyé avec succès")
    except Exception as e:
        status_label.config(text=f"Erreur : {e}")

# Interface graphique
root = Tk()
root.title("Client de messagerie sécurisée")

message_var = StringVar()

Label(root, text="Entrez votre message :").pack()
Entry(root, textvariable=message_var, width=50).pack()
Button(root, text="Envoyer", command=send_message).pack()
status_label = Label(root, text="")
status_label.pack()

root.mainloop()
