import pymongo


class UserHandler:
    def __init__(self):
        self.client = pymongo.MongoClient("mongodb://localhost:5001/")
        self.backend_db = self.client["BACKEND_DB"]
        self.user_collection = self.backend_db['users']

    def test_connection(self):
        print(self.client.list_database_names())

    def user_exists(self, username):
        query = {'user': username}
        user = self.user_collection.find_one(query, {'_id': 0})
        if user is None:
            return False
        else:
            return True

    def add_user(self, item):
        self.user_collection.insert_one(item)

    def get_user_by_username(self, username):
        # returns 'None' if no element is found.
        query = {'user': username}
        return self.user_collection.find_one(query, {'_id': 0})

    def update_user(self, username, new_element):
        query = {'user': username}
        update_field = {"$set": new_element}
        self.user_collection.update_one(query, update_field)


class ConversationHandler:
    def __init__(self):
        self.client = pymongo.MongoClient("mongodb://localhost:5001/")
        self.backend_db = self.client["BACKEND_DB"]
        self.conversation_collection = self.backend_db['conversations']

    def test_connection(self):
        print(self.client.list_database_names())

    def add_conversation(self, item):
        self.conversation_collection.insert_one(item)

    def conv_exists(self, usernames):
        query = {'users': {'$all': usernames, "$size": len(usernames)}}
        result = self.conversation_collection.find(query, {'_id': 0})

        if len(list(result)) == 0:
            return False
        else:
            return True

    def get_conversation_by_username(self, username):
        # returns 'None' if no element is found.
        query = {'users': {'$all': [username]}}
        return self.conversation_collection.find(query, {'_id': 0})

    def get_conversation_by_conv_id(self, conv_id):
        # returns 'None' if no element is found.
        query = {'conv-id': conv_id}
        return self.conversation_collection.find_one(query, {'_id': 0})
