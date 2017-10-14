# Flask
from flask import request, jsonify, make_response
# App
from app import app, db, google, facebook, api
# SQLAlchemy
from sqlalchemy.exc import IntegrityError
from app.models import User, SocialLogin, Post

# RESTful
from flask_restful import Resource, marshal_with, fields

# JWT
from app import jwt
from flask_restful import request

todo_fields = {
    'email': fields.Integer,
    'role': fields.String,
    'uri': fields.Url('todo', absolute=True),
}

class UserListResource(Resource):

    @jwt.jwt_required(soft=True)
    @marshal_with()
    def get(self):

        pass
