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

    def update_user(self, username, element_to_update):
        query = {'user': username}
        update_field = {"$set": element_to_update}
        self.user_collection.update_one(query, update_field)
