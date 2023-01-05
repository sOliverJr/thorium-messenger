from cryptography.fernet import Fernet
import hashlib
import base64


def encrypt(decrypted_message, key):
    fernet = Fernet(key)
    return fernet.encrypt(decrypted_message.encode())


def decrypt(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()


def decrypt_init_message(encrypted_message):
    fernet = Fernet(create_key('Maximilian Mustermann', 'muster_password'))
    return fernet.decrypt(encrypted_message).decode()


def create_key(username, password_hash):
    key_string = f'uname:{username}, pw_hash:{password_hash}'
    hash = hashlib.md5(key_string.encode()).hexdigest()
    return base64.urlsafe_b64encode(hash.encode())
