from server import database

user = {
    'user': 'oli',
    'passwort': 'test'
}

conversation = {
    'users': ['oli', 'sinah'],
    'conv-id': 'oli-sinah',
    'conv-encr-key': 'abcdefg'
}

uh = database.UserHandler()
ch = database.ConversationHandler()

# uh.add_user(user)
# ch.add_conversation(conversation)

# print(uh.get_user_by_username('oli'))

# for conversation in ch.get_conversation_by_username('oli'):
    # print(conversation)

usernames = ['sinah', ]
print(ch.test_if_conv_exists(usernames))
