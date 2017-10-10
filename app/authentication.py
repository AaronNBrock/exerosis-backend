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
import jwt
import datetime
import uuid
import json

from functools import wraps


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token required'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_users(current_user):
    if not current_user.id == 1:
        return jsonify({'message': 'Permission denied'})

    users = User.query.all()

    output = []

    for user in users:
        output.append(user.as_dict())

    return jsonify({'users': output})


@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):

    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({'message': 'User not found'})
    return jsonify({'user': user.as_dict()})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    access_token = data['access_token']
    provider_name = data['provider_name'].lower()

    if provider_name == 'google':
        me = google.get('userinfo', token=(access_token, ''))
        if 'error' in me.data:
            return jsonify({'error': me.data['error']})
        auth_data = {
            'name': me.data['name'],
            'email': me.data['email'],
            'picture_url': me.data['picture'],
            'provider_name': 'google',
            'provider_user_id': me.data['id']
        }

    elif provider_name == 'facebook':
        me = facebook.get('/me/?fields=email,name,id,picture.height(200).width(200)', token=(access_token, ''))
        if 'error' in me.data:
            return jsonify({'error': me.data['error']})
        auth_data = {
            'name': me.data['name'],
            'email': me.data['email'],
            'picture_url': me.data['picture']['data']['url'],
            'provider_name': 'facebook',
            'provider_user_id': me.data['id']
        }
    else:
        return jsonify({'error': 'Invalid Provider Id'})

    social_login = SocialLogin.query.filter_by(
        provider_name=auth_data['provider_name'],
        provider_user_id=auth_data['provider_user_id']
    ).first()

    # In case there's a login without a user
    if social_login is not None and social_login.user is None:
        social_login.delete()
        social_login = None

    is_new_user = False

    if social_login is None:
        is_new_user = True
        new_user = User(
            public_id=str(uuid.uuid4()),
            name=auth_data['name'],
            email=auth_data['email'],
            picture_url=auth_data['picture_url'],
        )

        social_login = SocialLogin(
            user=new_user,
            provider_name=auth_data['provider_name'],
            provider_user_id=auth_data['provider_user_id'],
        )
        db.session.add(new_user)
        db.session.commit()

    user = social_login.user

    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(weeks=4)},
                       app.config['SECRET_KEY'])

    return jsonify({'token': token.decode('UTF-8'), 'is_new_user': is_new_user})
