import socket

SERVER = "127.0.0.1"
PORT = 8787
ADDRESS = (SERVER, PORT)
HEADER = 64     # Length -> 64
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = '!DISCONNECT'

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)


def send(msg):
    message = msg.encode(FORMAT)
    message_length = len(message)
    send_length = str(message_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))

    client.send(send_length)     # Length of message
    client.send(message)         # Message


try:
    while True:
        message_content = input()
        send(message_content)
        if message_content == '!DISCONNECT':
            print("Caught Exit-command, exiting.")
            break
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting.")
    send('!DISCONNECT')
finally:
    ...

