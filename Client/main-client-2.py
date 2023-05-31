from cryptography.fernet import Fernet
import threading
import hashlib
import base64
import socket
import json


SERVER = "127.0.0.1"
PORT = 8787
ADDRESS = (SERVER, PORT)
ENCODING_FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'
MESSAGE_LENGTH = 1024

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)

# --- Encryption --- #

def encrypt(decrypted_message, key):
    fernet = Fernet(key)
    return fernet.encrypt(decrypted_message.encode())


def decrypt(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()


def create_key(username, password_hash):
    key_string = f'uname:{username}, pw_hash:{password_hash}'
    hash = hashlib.md5(key_string.encode()).hexdigest()
    key = base64.urlsafe_b64encode(hash.encode())
    return key


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


cryptography_key = ''
init_cryptography_key = create_key('Maximilian Mustermann', 'muster_password')
selected_conversation = ''

# -------------------- #


def send(decrypted_message, key):
    message = encrypt(decrypted_message, key)
    if len(message) <= MESSAGE_LENGTH:
        client.send(message)
    else:
        print('[CLIENT] Message to long, try again.')


def send_thread():
    global stop_threads
    global cryptography_key

    try:
        while not stop_threads:
            message_content = input()
            send(message_content, cryptography_key)

            if message_content == '!DISCONNECT':
                print("[AGENT] Caught exit-command, exiting.")
                stop_threads = True

        print('[AGENT] Send-thread killed')
    except KeyboardInterrupt:
        print('[SERVER] Send-thread detected keyboard interrupt, terminating connection.')
        send(DISCONNECT_MESSAGE, cryptography_key)
        stop_threads = True
        return False


def receive_thread(client):
    global stop_threads
    global cryptography_key

    try:
        while not stop_threads:
            message = decrypt(client.recv(MESSAGE_LENGTH), cryptography_key)
            print(message)

            if message == '[SERVER] Server shutting down.':
                stop_threads = True

        print('[AGENT] Receive-thread killed')
    except KeyboardInterrupt:
        print('[SERVER] Receive-thread detected keyboard interrupt, terminating connection.')
        send(DISCONNECT_MESSAGE, cryptography_key)
        stop_threads = True


def authenticate():
    global cryptography_key
    global init_cryptography_key

    user_is_authenticated = False
    print('Enter selection:')
    print('1: Login existing user')
    print('2: Create new user')

    while not user_is_authenticated:
        selection = input('Selection:')

        if selection == '1':
            username = get_valid_username()
            hashed_password = hash_password(get_valid_password())
            cryptography_key = create_key(username, hashed_password)

            init_message = f'login_user {username} {hashed_password}'

            send(init_message, init_cryptography_key)

            response = decrypt(client.recv(1024), cryptography_key)
            if response == f'[SERVER] Login successful, welcome {username}!':
                print(response)
                return True
            else:
                print(response)
                print('[CLIENT] Error, disconnecting.')
                return False
        elif selection == '2':
            username = get_valid_username()
            hashed_password = hash_password(create_valid_password())
            cryptography_key = create_key(username, hashed_password)

            init_message = f'create_user {username} {hashed_password}'

            send(init_message, init_cryptography_key)

            response = decrypt(client.recv(1024), cryptography_key)
            if response == f'[SERVER] User created successfully, welcome {username}!':
                print(response)
                return True
            else:
                print(response)
                print('[CLIENT] Error, disconnecting.')
                return False
        else:
            print('[CLIENT] Invalid input, try again.')


def get_valid_username():
    while True:
        username = input('Enter username:')
        if len(username.split()) != 1:
            print('Username cannot contain whitespaces, try again.')
        elif len(username) < 3:
            print('Username must be at least 3 characters long, try again.')
        else:
            return username


def get_valid_password():
    while True:
        password = input('Enter password:')
        if len(password.split()) != 1:
            print('Password cannot contain whitespaces, try again.')
        else:
            return password


def create_valid_password():
    while True:
        password_1 = input('Enter password:')
        if len(password_1.split()) != 1:
            print('Password cannot contain whitespaces, try again.')
        elif len(password_1) < 4:
            print('Password must contain at least 4 characters, try again.')
        else:
            password_2 = input('Confirm password:')
            if password_1 == password_2:
                return password_1
            else:
                print('Passwords do not match, try again.')


def chose_conversation():
    global selected_conversation
    message_json = decrypt(client.recv(MESSAGE_LENGTH), cryptography_key)
    message = json.loads(message_json)

    if message == '[SERVER] Server shutting down.':
        print('ALERTTTTTT!!!')

    print('Select conversation:')
    print('0: Create new Conversation')
    for index, conversation in enumerate(message):
        print(str(index + 1) + ': ' + conversation['conv-id'])

    input_is_valid = False
    while not input_is_valid:
        conversation_choice = input('Choice: ')
        try:
            conversation_choice = int(conversation_choice)
        except:
            print('[CLIENT] Please enter number.')
            continue
        if conversation_choice <= len(message):
            if conversation_choice == 0:
                input_is_valid = create_conversation()
            else:
                print(str(message[conversation_choice-1]['conv-id']))
                send('select_conversation ' + str(message[conversation_choice-1]['conv-id']), cryptography_key)
                response = decrypt(client.recv(1024), cryptography_key)
                if response == f'[SERVER] Conversation {str(message[conversation_choice-1]["conv-id"])} selected.':
                    print(f'[CLIENT] Conversation {str(message[conversation_choice-1]["conv-id"])} selected successfully.')
                    # selected_conversation = message[conversation_choice-1]
                    input_is_valid = True

        else:
            print('[CLIENT] Please enter valid option.')

        selected_conversation_json = decrypt(client.recv(MESSAGE_LENGTH), cryptography_key)
        selected_conversation = json.loads(selected_conversation_json)
        print(selected_conversation)


def create_conversation():
    global selected_conversation

    # Enter informations
    print('[CLIENT] Conversation wizard:')
    users = input('Please enter usernames: (!case-sensitive and whitespace-separated)')
    noise = input('Please enter noise:')

    send('create_conversation key ' + noise + ' users ' + users, cryptography_key)
    response = decrypt(client.recv(1024), cryptography_key)
    if response == '[SERVER] Conversation already exists.':
        print('[CLIENT] Conversation already exists.')
        chose_conversation()
        return True
    elif response == '[SERVER] Username(s) does not exist.':
        print('[CLIENT] Username(s) do not exist.')
        chose_conversation()
        return True
    elif response == '[SERVER] Conversation created successfully!':
        selected_conversation = json.loads(decrypt(client.recv(1024), cryptography_key))
        print('[CLIENT] Conversation created successfully.')
        return True


if __name__ == "__main__":
    authenticated = False

    try:
        stop_threads = False
        authenticated = authenticate()
    except KeyboardInterrupt:
        print("[AGENT] Caught keyboard interrupt, exiting.")
        stop_threads = True
        send(DISCONNECT_MESSAGE, init_cryptography_key)

    try:
        if authenticated:
            chose_conversation()

            threads = []

            threads.append(threading.Thread(target=receive_thread, args=(client,)))
            threads.append(threading.Thread(target=send_thread, args=()))

            for thread in threads:
                thread.daemon = True
                thread.start()

            # needs to be separate
            for thread in threads:
                thread.join()

    except KeyboardInterrupt:
        print("[AGENT] Caught keyboard interrupt, exiting.")
        stop_threads = True
        send(DISCONNECT_MESSAGE, cryptography_key)
