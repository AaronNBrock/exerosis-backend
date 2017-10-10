# Flask
from flask import request, jsonify, make_response, _request_ctx_stack
# App
from app import app, db, google, facebook, api
# SQLAlchemy
from app.models import User, SocialLogin, Post

# JWT
import jwt as pyjwt
from app import jwt

from flask_jwt import JWTError, _force_iterable

from datetime import datetime, timedelta
import uuid
import json


@jwt.payload_handler
def payload_handler(identity):
    iat = datetime.utcnow()
    exp = iat + app.config.get('JWT_EXPIRATION_DELTA')
    nbf = iat + app.config.get('JWT_NOT_BEFORE_DELTA')

    return {'exp': exp,
            'iat': iat,
            'nbf': nbf,
            'user_id': identity.id,
            'role': identity.role}


@jwt.identity_handler
def identity_handler(payload):
    user_id = payload['user_id']
    return User.query.filter_by(id=user_id).first()


@jwt.jwt_required_handler
def jwt_required_handler(*args, **kwargs):
    """Does the actual work of verifying the JWT data in the current request.
    This is done automatically for you by `jwt_required()` but you could call it manually.
    Doing so would be useful in the context of optional JWT access in your APIs.

    :param realm: an optional realm
    """
    if 0 < len(args):
        realm = args[0]
    elif 'realm' in kwargs:
        realm = kwargs['realm']
    else:
        realm = app.config['JWT_DEFAULT_REALM']

    if 1 < len(args):
        roles = args[1]
    elif 'roles' in kwargs:
        roles = kwargs['roles']
    else:
        roles = None

    if 2 < len(args):
        soft = args[1]
    elif 'soft' in kwargs:
        soft = kwargs['soft']
    else:
        soft = False

    token = jwt.request_callback()

    if token is None:
        if soft:
            jwt.current_identity = None
            _request_ctx_stack.top.current_identity = identity = None
            return
        else:
            raise JWTError('Authorization Required', 'Request does not contain an access token',
                           headers={'WWW-Authenticate': 'JWT realm="{}"'.format(realm)})

    try:
        payload = jwt.jwt_decode_callback(token)
    except pyjwt.InvalidTokenError as e:
        raise JWTError('Invalid token', str(e))

    if roles and 'role' in payload:
        role = payload['role']

        identity_role = _force_iterable(role)
        roles = _force_iterable(roles)

        if not identity_role or not set(roles).intersection(identity_role):
            raise JWTError('Bad Request', 'Permission Denied')
    jwt.current_identity = jwt.identity_callback(payload)
    _request_ctx_stack.top.current_identity = identity = jwt.current_identity

    if identity is None:
        raise JWTError('Invalid JWT', 'User does not exist')


@jwt.authentication_handler
def authenticate(provider_name, access_token, **kwargs):

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
    return user
