from Server.database import UserHandler

user_handler = UserHandler()

print(user_handler.test_connection())

obj = {
    'user': 'Oli',
    'address': "TestAddresse",
    'connection': "TestConnection"
}

user_handler.add_user(obj)
connection = {'connection': 'new TestConnection'}
user_handler.update_user('Oli', connection)
