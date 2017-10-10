# Flask
from flask import render_template, url_for, session, request, redirect, flash
# App
from app import app, db, google, facebook, api
# SQLAlchemy
from app.models import User, SocialLogin, Post
# RESTful
from flask_restful import Resource




# Logging in / Logging out
def create_user(auth_data):
    new_user = User(
        name=auth_data['name'],
        email=auth_data['email'],
        picture_url=auth_data['picture_url'],
    )

    new_social_login = SocialLogin(
        user=new_user,
        provider_id=auth_data['provider_id'],
        provider_user_id=auth_data['provider_user_id'],
    )

    db.session.add(new_user)
    db.session.commit()
    return new_user


def set_user(auth_data):
    social_login = SocialLogin.query.filter_by(
        provider_id=auth_data['provider_id'],
        provider_user_id=auth_data['provider_user_id'],
    ).first()

    # In case there's a login without a user
    if social_login is not None and social_login.user is None:
        social_login.delete()
        social_login = None

    if social_login is None:
        user = create_user(auth_data)
    else:
        user = social_login.user

    return user


@jwt.identity_handler
def identity(payload):
    user_id = payload['identity']
    return User.query.filter_by(id=user_id).first()

@jwt.authentication_handler
def authenticate(provider_id, access_token, **kwargs):
    provider_id = provider_id.lower()
    if provider_id == 'google':
        me = google.get('userinfo', token=(access_token, ''))
        auth_data = {
            'name': me.data['name'],
            'email': me.data['email'],
            'picture_url': me.data['picture'],
            'provider_id': 'google',
            'provider_user_id': me.data['id']
        }
    elif provider_id == 'facebook':
        me = facebook.get('/me/?fields=email,name,id,picture.height(200).width(200)', token=(access_token, ''))
        auth_data = {
            'name': me.data['name'],
            'email': me.data['email'],
            'picture_url': me.data['picture']['data']['url'],
            'provider_id': 'facebook',
            'provider_user_id': me.data['id']
        }
    else:
        return 'Invalid Provider Id'

    return set_user(auth_data)


class IdentityTest(Resource):
    decorators = [jwt_required()]

    def get(self):
        return {'hello': current_identity.name}

api.add_resource(IdentityTest, '/')
