import pymongo


class UserHandler:
    def __init__(self):
        self.client = pymongo.MongoClient("mongodb://localhost:5001/")
        self.backend_db = self.client["BACKEND_DB"]
        self.user_collection = self.backend_db['users']

    def test_connection(self):
        print(self.client.list_database_names())

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
