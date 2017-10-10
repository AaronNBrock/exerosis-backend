import datetime
from app import db, app


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), index=True, unique=True)
    name = db.Column(db.String(64), index=True)
    email = db.Column(db.String(128), index=True, unique=True, nullable=False)
    picture_url = db.Column(db.String)
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())

    roll = db.Column(db.Enum('admin', 'moderator', 'user'), default='user')

    social_logins = db.relationship('SocialLogin', backref='user', cascade='all, delete-orphan')
    posts = db.relationship('Post', backref='author', cascade='save-update, merge')

    def __repr__(self):
        return '<User {}>'.format(self.name)

    def as_dict(self):
        return {
            'id': self.id,
            'public_id': self.public_id,
            'name': self.name,
            'email': self.email,
            'picture_url': self.picture_url,
            'created': self.created,
            'roll': self.roll
        }


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

