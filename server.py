from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os, base64

app = Flask(__name__)

# Base de données simulée : utilisateurs et messages
users = {}  # Structure : { "username": { "password": "hashed_password", "salt": salt } }
messages = {}  # Structure : { "recipient": [ { "sender": "user1", "message": "encrypted_message" } ] }

# Fonction pour dériver une clé AES à partir du mot de passe d'un utilisateur
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Fonction de chiffrement AES
def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message).decode()

# Fonction de déchiffrement AES
def decrypt_message(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    encrypted_content = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_content) + decryptor.finalize()
    return decrypted_message.decode()

# Route pour enregistrer un utilisateur
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if username in users:
        return jsonify({"error": "Utilisateur déjà enregistré"}), 400

    salt = os.urandom(16)
    users[username] = { "password": password, "salt": salt }
    messages[username] = []  # Crée une boîte de réception vide
    return jsonify({"message": "Utilisateur enregistré avec succès"}), 201

# Route pour envoyer un message
@app.route('/send_message', methods=['POST'])
def send_message():
    sender = request.json.get('sender')
    recipient = request.json.get('recipient')
    message = request.json.get('message')
    password = request.json.get('password')

    if sender not in users or recipient not in users:
        return jsonify({"error": "Utilisateur non trouvé"}), 404

    # Dériver la clé de l'expéditeur
    sender_salt = users[sender]["salt"]
    key = derive_key(password, sender_salt)

    # Chiffrer le message
    encrypted_message = encrypt_message(message, key)

    # Ajouter le message à la boîte de réception du destinataire
    messages[recipient].append({ "sender": sender, "message": encrypted_message })
    return jsonify({"message": "Message envoyé avec succès"}), 200

# Route pour récupérer les messages d'un utilisateur
@app.route('/get_messages', methods=['POST'])
def get_messages():
    username = request.json.get('username')
    password = request.json.get('password')

    if username not in users:
        return jsonify({"error": "Utilisateur non trouvé"}), 404

    # Dériver la clé de l'utilisateur
    user_salt = users[username]["salt"]
    key = derive_key(password, user_salt)

    # Déchiffrer tous les messages de la boîte de réception
    decrypted_messages = []
    for msg in messages[username]:
        try:
            decrypted_content = decrypt_message(msg["message"], key)
            decrypted_messages.append({ "sender": msg["sender"], "message": decrypted_content })
        except Exception as e:
            decrypted_messages.append({ "sender": msg["sender"], "message": "Impossible de déchiffrer le message" })

    return jsonify({"messages": decrypted_messages}), 200

# Lancement du serveur Flask
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
