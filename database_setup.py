from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer,
                          BadSignature,
                          SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(
    string.ascii_uppercase +
    string.digits) for x in range(32))


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    password_hash = Column(String(250))

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return{
            'id': self.id,
            'name': self.name,
            'email': self.email
        }

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


class Rate(Base):
    __tablename__ = 'rate'

    id = Column(Integer, primary_key=True)
    rate = Column(Integer)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return{
            'id': self.id,
            'rate': self.rate
        }


class MeatType(Base):
    __tablename__ = 'meat_type'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
        }


class Place(Base):
    __tablename__ = 'place'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    lat = Column(String(50))
    lon = Column(String(50))
    picture = Column(String(250))
    rate_id = Column(Integer, ForeignKey('rate.id'))
    rate = relationship(Rate)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'rate': {
                'id': self.rate.id,
                'rate': self.rate.rate
            },
            'id': self.id
        }


class Taco(Base):
    __tablename__ = 'taco'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    price = Column(String(8))
    picture = Column(String(250))
    meat_type_id = Column(Integer, ForeignKey('meat_type.id'))
    meat_type = relationship(MeatType)
    place_id = Column(Integer, ForeignKey('place.id'))
    place = relationship(Place)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'picture': self.picture,
            'meatType': {
                'id': self.meat_type.id,
                'name': self.meat_type.name,
            }

        }


#engine = create_engine('sqlite:///best_tacos.db')
engine = create_engine('postgres://besttacos:XXXXX@localhost:5432/besttacos')
Base.metadata.create_all(engine)
