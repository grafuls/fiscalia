from datetime import datetime

from config import SECRET
from flask_login import UserMixin
from flask_mongoengine import MongoEngine
from flask_security import RoleMixin
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from mongoengine import GeoPointField

db = MongoEngine()


class Role(db.Document, RoleMixin):
    name = db.StringField(max_length=80, unique=True)
    filter = db.StringField(max_length=255)
    description = db.StringField(max_length=255)


class User(db.Document, UserMixin):
    username = db.StringField(max_length=255, required=True, unique=True)
    email = db.EmailField()
    password = db.StringField(max_length=255, required=True)
    active = db.BooleanField(default=True)
    roles = db.ListField(db.ReferenceField(Role), default=[])
    first_login = db.BooleanField(default=True)
    accepted_tac = db.BooleanField(default=False)

    meta = {
        'strict': False
    }

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_auth_token(self):
        serializer = URLSafeTimedSerializer(SECRET)
        return serializer.dumps({'username': self.username, 'password': self.password})

    def has_role(self, role):
        """Returns `True` if the user identifies with the specified role.

        :param role: A role name or `Role` instance"""
        if isinstance(role, str):
            return role in (role.name for role in self.roles)
        else:
            return role in self.roles


class Circuit(db.Document):
    name = db.StringField()
    location = GeoPointField()


class Counter(db.EmbeddedDocument):
    count = db.IntField(default=0)
    enabled = db.BooleanField(default=True)


class Votes(db.Document):
    president = db.EmbeddedDocumentField(Counter)
    vice_president = db.EmbeddedDocumentField(Counter)
    gobernor = db.EmbeddedDocumentField(Counter)
    diputado = db.EmbeddedDocumentField(Counter)
    senador = db.EmbeddedDocumentField(Counter)
    intendente = db.EmbeddedDocumentField(Counter)
    general = db.EmbeddedDocumentField(Counter)


class Party(db.Document):
    name = db.StringField()
    votes = db.ReferenceField(Votes)


class OtherVotes(db.Document):
    blank = db.ReferenceField(Votes)
    nulled = db.ReferenceField(Votes)
    recurrent = db.ReferenceField(Votes)
    refuted = db.ReferenceField(Votes)


class Box(db.Document):
    number = db.IntField()
    parties = db.ListField(db.ReferenceField(Party))
    other_votes = db.ReferenceField(OtherVotes)
    last_updated = db.DateTimeField(default=datetime.now())


class Voter(db.Document):
    order = db.IntField()
    name = db.StringField(max_length=80)
    dni = db.LongField(unique=True)
    category = db.IntField()
    address = db.StringField(max_length=255)
    location = GeoPointField()
    type_dni = db.StringField()
    status = db.IntField(default=4)
    ultimate_status = db.IntField(default=4)
    box = db.ReferenceField(Box)
    circuit = db.ReferenceField(Circuit)
    located = db.BooleanField(default=False)
    last_updated = db.DateTimeField(default=datetime.now())

    meta = {
        'indexes': [
            {
                'fields': ['$order']
            }
        ],
        'strict': False
    }

    def get_edad(self):
        now = datetime.now()
        return now.year - self.category
