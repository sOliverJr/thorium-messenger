import socket
import threading

SERVER = "127.0.0.1"
PORT = 8787
ADDRESS = (SERVER, PORT)
HEADER = 64     # Length -> 64
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)


def handle_client(connection, address):
    print(f'[NEW CONNECTION] {address} connected.')
    connected = True
    while connected:
        message_length = connection.recv(HEADER).decode(FORMAT)    # Get message-length from header
        # If message is not Null
        if message_length:
            message_length = int(message_length)
            message = connection.recv(message_length).decode(FORMAT)
            if message == DISCONNECT_MESSAGE:
                connected = False
                print(f'[{address}] disconnected.')
            else:
                print(f'[{address}] {message}')

    connection.close()


def start():
    server.listen()
    print(f'[LISTENING] Server is listening on {SERVER}:{PORT}')
    while True:
        connection, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(connection, address))
        thread.start()
        print(f'[ACTIVE CONNECTIONS] {threading.active_count() - 1}')   # Minus main-thread


print('[SERVER] Server is starting...')
start()
