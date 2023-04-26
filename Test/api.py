from flask import Flask, request
from flask_restful import Resource, Api, reqparse
import ast

app = Flask(__name__)
api = Api(app)


# Paths
class Test(Resource):
    ...


class Ping(Resource):
    def post(self):
        parser = reqparse.RequestParser()  # initialize
        parser.add_argument('value', required=True)  # add arg(s)
        parser.add_argument('test', required=True)  # add arg(s)
        args = parser.parse_args()  # parse arguments to dictionary

        print(args)
        # self.value = args['value']
        # return {'new_value': self.value}, 200

    def get(self):
        return {'backend': 'running', 'value': self.value}, 200


api.add_resource(Test, '/test')
api.add_resource(Ping, '/ping')


# Start Flask app
if __name__ == '__main__':
    app.run()
