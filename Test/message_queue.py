import redis
import pprint

r = redis.Redis(
    host="localhost", port=6379,
    password="FukYu"
)
message_send = {'oli': 'helllooo'}
# r.xadd(name='first_message', fields=message_send, id='*')


# In der Dokumentation steht '$', geht aber nicht, deswegen b"0-0"
last_message_id = b"0-0"
while True:
    events = r.xread({"first_message": last_message_id})
    for stream, messages in events:
        for message_id, message in messages:
            last_message_id = message_id
            print(message[b'user'].decode("utf-8") + ': ' + message[b'msg'].decode("utf-8"))
