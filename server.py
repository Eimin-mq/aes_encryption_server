from flask import Flask, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

app = Flask(__name__)

# Clé AES (doit être identique pour le client et le serveur)
AES_KEY = os.urandom(32)

def decrypt_message(encrypted_message):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_message) + decryptor.finalize()

@app.route('/send_message', methods=['POST'])
def receive_message():
    encrypted_message = request.data
    decrypted_message = decrypt_message(encrypted_message)
    print(f"Message reçu : {decrypted_message.decode('utf-8')}")
    return "Message reçu avec succès", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
