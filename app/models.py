import datetime
import enum
from app import db, app
from app import jwt


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    public_id = db.Column(db.String(50), index=True, unique=True)

    name = db.Column(db.String(64), index=True)
    name.read = ['admin', 'moderator', '']
    name.write = []

    email = db.Column(db.String(128), index=True, unique=True, nullable=False)
    role = db.Column(db.Enum('admin', 'moderator', 'user', 'banned'), default='user')
    picture_url = db.Column(db.String)
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())


    social_logins = db.relationship('SocialLogin', backref='user', cascade='all, delete-orphan')
    posts = db.relationship('Post', backref='author', cascade='save-update, merge')

    def __repr__(self):
        return '<User {}>'.format(self.name)

    def as_dict(self, user=None):
        if user is None:
            user = jwt.current_identity

        if user:
            role = user.role
        else:
            role = 'banned'

        user_data = {}

        if role in ['admin']:
            user_data['id'] = self.id
        user_data['public_id'] = self.public_id
        user_data['name'] = self.name
        if role in ['admin', 'moderator']:
            user_data['email'] = self.email
        if role in ['admin', 'moderator']:
            user_data['role'] = self.role
        user_data['picture_url'] = self.picture_url
        if role in ['admin', 'moderator']:
            user_data['created'] = self.created


        return user_data


class SocialLogin(db.Model):
    __tablename__ = 'social_logins'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    provider_name = db.Column(db.String, nullable=False)
    provider_user_id = db.Column(db.String, nullable=False)

    def __repr__(self):
        return '<SocialLogin id:{} user_id:{}>'.format(self.provider_id, self.user_id)


class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64))
    image_url = db.Column(db.String)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())

    def __repr__(self):
        return '<Post {}>'.format(self.title)

