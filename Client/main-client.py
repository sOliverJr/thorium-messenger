import socket
import threading

SERVER = "127.0.0.1"
PORT = 8787
ADDRESS = (SERVER, PORT)
ENCODING_FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'
MESSAGE_LENGTH = 1024

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)


def send(msg):
    message = msg.encode(ENCODING_FORMAT)
    if len(message) <= MESSAGE_LENGTH:
        client.send(message)
    else:
        print('[CLIENT] Message to long, try again.')


def send_thread():
    global stop_threads

    try:
        while not stop_threads:
            # message_content = input('>')
            message_content = input()
            send(message_content)

            if message_content == '!DISCONNECT':
                print("[AGENT] Caught exit-command, exiting.")
                stop_threads = True

        print('[AGENT] Send-thread killed')
    except KeyboardInterrupt:
        print('[SERVER] Send-thread detected keyboard interrupt, terminating connection.')
        send(DISCONNECT_MESSAGE)
        stop_threads = True


def receive_thread(client):
    global stop_threads

    try:
        while not stop_threads:
            message = client.recv(MESSAGE_LENGTH).decode(ENCODING_FORMAT)
            print(message)

            if message == '[SERVER] Server shutting down.':
                stop_threads = True

        print('[AGENT] Receive-thread killed')
    except KeyboardInterrupt:
        print('[SERVER] Receive-thread detected keyboard interrupt, terminating connection.')
        send(DISCONNECT_MESSAGE)
        stop_threads = True


def authenticate():
    authenticated = False
    print('Enter selection:')
    print('1: Login existing user')
    print('2: Create new user')

    while not authenticated:
        selection = input('Selection:')

        if selection == '1':
            username = get_valid_username()
            password = get_valid_password()
            send(f'login_user {username} {password}')

            response = client.recv(1024).decode(ENCODING_FORMAT)
            if response == f'Login successful, welcome {username}!':
                print(response)
                return True
            else:
                print('[CLIENT] Error, disconnecting.')
                return False
        elif selection == '2':
            username = get_valid_username()
            password = create_valid_password()
            send(f'create_user {username} {password}')

            response = client.recv(1024).decode(ENCODING_FORMAT)
            if response == f'User created successfully, welcome {username}!':
                print(response)
                return True
            else:
                print('[CLIENT] Error, disconnecting.')
                return False
        else:
            print('Invalid input, try again.')


def get_valid_username():
    while True:
        username = input('Enter username:')
        if len(username.split()) != 1:
            print('Username cannot contain whitespaces, try again.')
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
        else:
            password_2 = input('Confirm password:')
            if password_1 == password_2:
                return password_1
            else:
                print('Passwords do not match, try again.')


try:
    stop_threads = False

    authenticated = authenticate()

    if authenticated:
        receiving_thread = threading.Thread(target=receive_thread, args=(client,))
        receiving_thread.start()

        receiving_thread = threading.Thread(target=send_thread, args=())
        receiving_thread.start()

except KeyboardInterrupt:
    print("[AGENT] Caught keyboard interrupt, exiting.")
    stop_threads = True
    send(DISCONNECT_MESSAGE)

