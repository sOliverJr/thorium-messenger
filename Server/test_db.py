import database

user = {
    'user': 'oli',
    'passwort': 'test'
}

uh = database.UserHandler()

# uh.add_user(user)

print(uh.get_user_by_username('oli'))
