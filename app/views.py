# Flask
from flask import request, jsonify, make_response
# App
from app import app, db, google, facebook, api
# SQLAlchemy
from sqlalchemy.exc import IntegrityError
from app.models import User, SocialLogin, Post

# RESTful
from flask_restful import Resource

# JWT
from app import jwt

from flask_restful import request


@app.route('/user', methods=['GET'])
@jwt.jwt_required(soft=True)
def get_users():
    users = User.query.all()
    output = []
    for user in users:
        output.append(user.as_dict())
    return jsonify({'users': output})


class UserManagement(Resource):
    @jwt.jwt_required(soft=True)
    def get(self, public_id):
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404
        return jsonify({'user': user.as_dict()})

    @jwt.jwt_required(roles='admin')
    def post(self, public_id):
        data = request.get_json()
        if not isinstance(data, dict):
            return jsonify({'Bad Request', 'Data must be in JSON.'})
        user = User.query.filter_by(public_id=public_id).first()

        success = {}
        failure = {}
        for key, value in data.items():
            if hasattr(user, key) and not key.startswith('_'):
                setattr(user, key, value)
                success[key] = value
            else:
                failure[key] = value
        db.session.commit()
        resp = {}
        if success:
            resp['success'] = success
        if failure:
            resp['failure'] = failure

        return jsonify(resp)

    @jwt.jwt_required(roles='admin')
    def delete(self, public_id):
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return jsonify({'message': 'User not found'})
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted'})


class ProfileManagement(Resource):
    @jwt.jwt_required(soft=True)
    def get(self):
        user = jwt.current_identity
        if not user:
            return jsonify({'message': 'User not found'}), 404
        return jsonify({'user': user.as_dict()})


api.add_resource(ProfileManagement, '/profile')
api.add_resource(UserManagement, '/user/<string:public_id>')


