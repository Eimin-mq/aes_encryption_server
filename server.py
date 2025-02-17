from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os, base64

app = Flask(__name__)

# Génération d'une clé de chiffrement
password = b"mot_de_passe_secret"  # À personnaliser
salt = os.urandom(16)
backend = default_backend()

from cryptography.hazmat.primitives import hashes

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),  # Correction ici
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

key = kdf.derive(password)  # Clé dérivée de la phrase secrète

# Fonction de chiffrement AES
def encrypt_message(message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message).decode()

# Fonction de déchiffrement AES
def decrypt_message(encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    encrypted_content = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_content) + decryptor.finalize()
    return decrypted_message.decode()

# Route API pour chiffrer un message
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json.get('message', '')
    encrypted_message = encrypt_message(data)
    return jsonify({'encrypted_message': encrypted_message})

# Route API pour déchiffrer un message
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json.get('encrypted_message', '')
    decrypted_message = decrypt_message(data)
    return jsonify({'decrypted_message': decrypted_message})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
