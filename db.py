'''
db
database file, containing all the logic to interface with the sql database
'''

import base64
import os
from pathlib import Path

import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from models import *
from sqlalchemy import create_engine, or_
from sqlalchemy.orm import Session
from werkzeug.security import check_password_hash, generate_password_hash

# creates the database directory
Path("database").mkdir(exist_ok=True)

# "database/main.db" specifies the database file
engine = create_engine("sqlite:///database/main.db", echo=False)

# initializes the database
Base.metadata.create_all(engine)

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt), salt

def insert_user(username: str, password: str):
    hashed_password, salt = hash_password(password)
    with Session(engine) as session:
        user = User(username=username, password=hashed_password.decode('utf-8'), salt=salt)
        session.add(user)
        session.commit()

def get_user(username: str):
    with Session(engine) as session:
        return session.query(User).filter_by(username=username).first()

def get_friends(username: str):
    with Session(engine) as session:
        user = session.get(User, username)
        if not user:
            return None
        friends = session.query(User).join(Friendship, or_(
            Friendship.friend_username == User.username,
            Friendship.user_username == User.username
        )).filter(User.username != username).all()
        return [friend.username for friend in friends]

def add_friend(sender_username: str, receiver_username: str):
    with Session(engine) as session:
        sender = session.get(User, sender_username)
        receiver = session.get(User, receiver_username)
        if not sender or not receiver:
            return "One or both users do not exist."
        if session.query(Friendship).filter(or_(
                (Friendship.user_username == sender_username) & (Friendship.friend_username == receiver_username),
                (Friendship.user_username == receiver_username) & (Friendship.friend_username == sender_username)
            )).first():
            return "Already friends."
        friend_request = FriendRequest(sender_username=sender_username, receiver_username=receiver_username)
        session.add(friend_request)
        session.commit()
        return "Friend request sent."

def get_received_friend_requests(username: str):
    with Session(engine) as session:
        user = session.get(User, username)
        if not user:
            return None
        requests = session.query(FriendRequest).filter_by(receiver_username=username, accepted=False).all()
        return [(request.id, request.sender_username) for request in requests]

def get_sent_friend_requests(username: str):
    with Session(engine) as session:
        user = session.get(User, username)
        if not user:
            return None
        requests = session.query(FriendRequest).filter_by(sender_username=username, accepted=False).all()
        return [(request.id, request.receiver_username) for request in requests]

def respond_to_friend_request(request_id: int, accept: bool):
    with Session(engine) as session:
        friend_request = session.get(FriendRequest, request_id)
        if not friend_request:
            return "Friend request not found."
        if accept:
            new_friendship1 = Friendship(user_username=friend_request.sender_username, friend_username=friend_request.receiver_username)
            new_friendship2 = Friendship(user_username=friend_request.receiver_username, friend_username=friend_request.sender_username)
            session.add(new_friendship1)
            session.add(new_friendship2)
            friend_request.accepted = True
            session.commit()
            return "Friend request accepted."
        else:
            session.delete(friend_request)
            session.commit()
            return "Friend request rejected."

# New functions for messages using encryption
def save_message(sender_username, receiver_username, content, room_id):
    with Session(engine) as session:
        message = Message(sender_username=sender_username, receiver_username=receiver_username, content=content, room_id=room_id)
        session.add(message)
        session.commit()

def get_messages_by_room_id(room_id):
    with Session(engine) as session:
        messages = session.query(Message).filter_by(room_id=room_id).all()
        return [(msg.sender_username, msg.receiver_username, msg.content, msg.timestamp) for msg in messages]
