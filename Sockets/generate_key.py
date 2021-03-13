import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

#para la encriptacion del texto se utiliza un algoritmo AES (Advanced Encryption Standard) junto con standard padding PKCS7

def get_key(word):
    password_provided = word  
    password = password_provided.encode()  # Convertimos el mensaje a bytes
    salt = b'salt_'  
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1000,
    backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) 
    return key

def encrypt(message,key):
    message_2 = message.encode()
    f = Fernet(key)
    encrypted = f.encrypt(message_2)
    return encrypted.decode('utf-8')

def decrypt(message_enc,key):
    encrypted = message_enc.encode('utf-8')
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return decrypted.decode('utf-8')
    
