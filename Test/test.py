import json

user_array = ['oli', 'sinah']
conv_id = 'oli-sinah'
conv_encr_key = 'encryption_key'


new_conversation = {
        'users': user_array,
        'conv-id': conv_id,
        'encryption_key': conv_encr_key
}
print(new_conversation)

new_conversation_json = json.dumps(new_conversation)

print(new_conversation_json)