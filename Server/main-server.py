import socket
import threading
import time

SERVER = "127.0.0.1"
PORT = 8787
ADDRESS = (SERVER, PORT)
ENCODING_FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'
MESSAGE_LENGTH = 1024

# Format: {'username': connection}
active_connections = {}
# Format: {'username': 'password'}
login_credentials = {'oli': 'test'}
server_running = True

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)


def send_message(connection, msg):
    message = msg.encode(ENCODING_FORMAT)
    connection.send(message)


def broadcast_message(msg, exception_username):
    message = msg.encode(ENCODING_FORMAT)
    for username in active_connections:
        if username != exception_username:
            active_connections[username].send(message)


def receive_message(username):
    while True:
        try:
            message = active_connections[username].recv(MESSAGE_LENGTH).decode(ENCODING_FORMAT)

            # If client wants to disconnect
            if message == DISCONNECT_MESSAGE:
                disconnect_user_by_username(username, '[SERVER] Request accepted, disconnecting.')
                broadcast_message(f'[SERVER] {username} disconnected.', username)
                return False

            print(f'[{username}] {message}')
            broadcast_message(f'[{username}] {message}', username)

        except Exception as e:
            print(f'Exception: {str(e)}')
            if username in active_connections:
                disconnect_user_by_username(username, f'[SERVER] An error occurred, kicking {username}.')
            return False


def authenticate_user(auth_array, connection):
    username = auth_array[0]
    if username not in login_credentials:
        disconnect_user_by_connection(connection, '[SERVER] Username unknown, disconnecting.')
        return False
    if auth_array[1] == login_credentials[username]:
        active_connections[username] = connection
        send_message(connection, f'Login successful, welcome {username}!')
        return True
    else:
        # if username in active_connections:
        #   disconnect_user_by_username(auth_array[0], '[SERVER] Username and password do not match, disconnecting.')
        disconnect_user_by_connection(connection, '[SERVER] Username and password do not match, disconnecting.')
        return False


def create_user(auth_array, connection):
    username = auth_array[0]
    if username in login_credentials:
        disconnect_user_by_connection(connection, '[SERVER] Username already exists, disconnecting.')
        return False
    active_connections[username] = connection
    login_credentials[username] = auth_array[1]
    send_message(connection, f'User created successfully, welcome {username}!')
    return True


def disconnect_user_by_username(username, message):
    active_connections.get(username).send(message.encode(ENCODING_FORMAT))
    active_connections.get(username).close()
    del active_connections[username]
    print(f'[SERVER] Disconnected {username}.')


def disconnect_user_by_connection(connection, message):
    connection.send(message.encode(ENCODING_FORMAT))
    connection.close()
    print(f'[SERVER] Terminated unknown connection.')


def disconnect_all():
    active_connections_copy = active_connections.copy()
    for username in active_connections_copy:
        disconnect_user_by_username(username, '[SERVER] Terminating connection.')


def handle_client(connection):
    global server_running

    init_message = connection.recv(MESSAGE_LENGTH).decode(ENCODING_FORMAT)
    auth_successful = False

    # Turns init_message in array: request, username, password
    init_message_split = init_message.split()

    # Returns request-type (create_user or login_user) and deletes field from array
    request = init_message_split.pop(0)

    if request == 'create_user':
        auth_successful = create_user(init_message_split, connection)
    elif request == 'login_user':
        auth_successful = authenticate_user(init_message_split, connection)
    else:
        auth_successful = False
        disconnect_user_by_connection(connection, '[SERVER] Bad request, disconnecting.')

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
