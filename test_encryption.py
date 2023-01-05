import base64
import hashlib
from cryptography.fernet import Fernet


def encrypt(decrypted_message, key):
    fernet = Fernet(key)
    return fernet.encrypt(decrypted_message.encode())


def decrypt(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()


def create_key(username, password):
    key_string = f'uname:{username}, pw:{password}'
    hash = hashlib.md5(key_string.encode()).hexdigest()
    return base64.urlsafe_b64encode(hash.encode())


key = create_key('oli', 'test')
message = 'Hello World!'

encrypted_message = encrypt(message, key)
print(encrypted_message)

decrypted_message = decrypt(encrypted_message, key)
print(decrypted_message)
