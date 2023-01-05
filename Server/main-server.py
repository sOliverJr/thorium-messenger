from encryption import create_key, encrypt, decrypt, decrypt_init_message
import threading
import database
import socket
import time

SERVER = "127.0.0.1"
PORT = 8787
ADDRESS = (SERVER, PORT)
ENCODING_FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'
MESSAGE_LENGTH = 1024

# Format: {'username': connection}
active_connections = {}

# Format: {'username': encryption_key}
active_encryption_keys = {}

server_running = True

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)

user_db = database.UserHandler()


def send_message_by_connection(connection, msg, encryption_key):
    message = encrypt(msg, encryption_key)
    connection.send(message)


def send_message_by_username(username, decrypted_message):
    connection = active_connections[username]
    encrypted_message = encrypt(decrypted_message, active_encryption_keys[username])
    connection.send(encrypted_message)


def broadcast_message(msg, exception_username):
    for username in active_connections:
        if username != exception_username:
            send_message_by_username(username, msg)


def receive_message(username):
    global active_connections
    global active_encryption_keys
    while True:
        try:
            encrypted_message = active_connections[username].recv(MESSAGE_LENGTH)
            decrypted_message = decrypt(encrypted_message, active_encryption_keys[username])

            # If client wants to disconnect
            if decrypted_message == DISCONNECT_MESSAGE:
                disconnect_user_by_username(username, '[SERVER] Request accepted, disconnecting.')
                broadcast_message(f'[SERVER] {username} disconnected.', username)
                return False

            print(f'[{username}] {decrypted_message}')
            broadcast_message(f'[{username}] {decrypted_message}', username)

        except Exception as e:
            print(f'Exception in {username}´s thread: {repr(e)}')
            if username in active_connections:
                disconnect_user_by_username(username, f'[SERVER] An error occurred, kicking {username}.')
            return False


def authenticate_user(auth_array, connection):
    username = auth_array[0]
    password_hash = auth_array[1]
    key = create_key(username, password_hash)

    user = user_db.get_user_by_username(username)
    if user is None:
        disconnect_user_by_connection(connection, '[SERVER] Username unknown, disconnecting.', key)
        return False
    if password_hash == user['password_hash']:
        active_connections[username] = connection
        active_encryption_keys[username] = user['encryption_key']
        send_message_by_connection(connection, f'[SERVER] Login successful, welcome {username}!', user['encryption_key'])
        return True
    else:
        disconnect_user_by_connection(connection, '[SERVER] Username and password do not match, disconnecting.', key)
        return False


def create_user(auth_array, connection):
    username = auth_array[0]
    password_hash = auth_array[1]

    user = user_db.get_user_by_username(username)
    if user is not None:
        key = create_key(username, password_hash)
        disconnect_user_by_connection(connection, '[SERVER] Username already exists, disconnecting.', key)
        return False

    encryption_key = create_key(username, password_hash)
    active_connections[username] = connection
    active_encryption_keys[username] = encryption_key
    new_user = {
        'user': username,
        'password_hash': password_hash,
        'encryption_key': encryption_key
    }
    user_db.add_user(new_user)
    send_message_by_connection(connection, f'[SERVER] User created successfully, welcome {username}!', encryption_key)
    return True


def disconnect_user_by_username(username, message):
    send_message_by_username(username, message)
    active_connections.get(username).close()
    del active_connections[username]
    del active_encryption_keys[username]
    print(f'[SERVER] Disconnected {username}.')


def disconnect_user_by_connection(connection, message, encryption_key):
    send_message_by_connection(connection, message, encryption_key)
    connection.close()
    print(f'[SERVER] Terminated unknown connection.')


def disconnect_all():
    active_connections_copy = active_connections.copy()
    for username in active_connections_copy:
        disconnect_user_by_username(username, '[SERVER] Terminating connection.')


def handle_client(connection):
    global server_running

    encrypted_init_message = connection.recv(MESSAGE_LENGTH)
    decrypted_init_message = decrypt_init_message(encrypted_init_message)

    # Turns init_message in array: request, username, password
    init_message_split = decrypted_init_message.split()

    # Returns request-type (create_user or login_user) and deletes field from array
    request = init_message_split.pop(0)

    if request == 'create_user':
        auth_successful = create_user(init_message_split, connection)
    elif request == 'login_user':
        auth_successful = authenticate_user(init_message_split, connection)
    else:
        auth_successful = False
        # disconnect_user_by_connection(connection, '[SERVER] Bad request, disconnecting.')

    try:
        if auth_successful:
            username = init_message_split[0]
            print(f'[SERVER] {username} joined the Server!')
            broadcast_message(f'[SERVER] {username} joined the Server!', username)

            client_is_connected = True
            while server_running and client_is_connected:
                try:
                    client_is_connected = receive_message(username)
                except:
                    break
        else:
            print('[SERVER] Authentication failed.')

    except KeyboardInterrupt:
        print("[CLIENT HANDLER] Caught keyboard interrupt, exiting.")
        # Username with empty string would be skipped by message!
        broadcast_message('[SERVER] Server shutting down.', '')
        disconnect_all()
        server.close()
        server_running = False


def start():
    global server_running
    server.listen()
    print(f'[LISTENING] server.py is listening on {SERVER}:{PORT}')
    try:
        while server_running:
            connection, address = server.accept()
            print(f'[NEW CONNECTION] {address} connected.')

            thread = threading.Thread(target=handle_client, args=(connection,))
            thread.start()

    except KeyboardInterrupt:
        print("[AGENT] Caught keyboard interrupt, exiting.")
        # Username with empty string would be skipped by message!
        broadcast_message('[SERVER] Server shutting down.', '')
        time.sleep(1)

        disconnect_all()
        time.sleep(1)

        server.close()
        server_running = False


print('[SERVER] server.py is starting...')
start()
