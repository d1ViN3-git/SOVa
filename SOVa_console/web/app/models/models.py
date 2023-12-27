from . import db
from flask_login import UserMixin
from sqlalchemy import Column, Integer, DateTime, String, TEXT

class SIB(db.Model):
    __tablename__ = 'sib'

    id = Column(Integer, primary_key=True)
    date = Column(DateTime, nullable=False)
    point = Column(String(50), nullable=False)
    module = Column(String(50), nullable=False)
    data = Column(TEXT, nullable=False)
    
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(32), nullable=False, unique=True)
    password = Column(String(300), nullable=False, unique=True)