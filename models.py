'''
models
defines sql alchemy data models
also contains the definition for the room class used to keep track of socket.io rooms

Just a sidenote, using SQLAlchemy is a pain. If you want to go above and beyond, 
do this whole project in Node.js + Express and use Prisma instead, 
Prisma docs also looks so much better in comparison

or use SQLite, if you're not into fancy ORMs (but be mindful of Injection attacks :) )
'''

from datetime import datetime
from typing import Dict

from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer,
                        LargeBinary, String)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# data models
class Base(DeclarativeBase):
    pass

# model to store user information
class User(Base):
    __tablename__ = "user"
    username: Mapped[str] = mapped_column(String, primary_key=True)
    password: Mapped[str] = mapped_column(String)
    salt: Mapped[bytes] = mapped_column(LargeBinary)  # Salt for password-based key derivation
    
    # Relationships
    friends = relationship("Friendship", foreign_keys="[Friendship.user_username]",
                           primaryjoin="User.username==Friendship.user_username",
                           back_populates="user")
    received_requests = relationship("FriendRequest",
                                     foreign_keys="[FriendRequest.receiver_username]",
                                     back_populates="receiver")
    sent_requests = relationship("FriendRequest",
                                 foreign_keys="[FriendRequest.sender_username]",
                                 back_populates="sender")
    sent_messages = relationship("Message", foreign_keys="[Message.sender_username]",
                                 back_populates="sender")
    received_messages = relationship("Message", foreign_keys="[Message.receiver_username]",
                                     back_populates="receiver")

class Room(Base):
    __tablename__ = 'room'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String)  # Optional: For named rooms

class Message(Base):
    __tablename__ = 'message'
    id = Column(Integer, primary_key=True)
    sender_username = Column(String, ForeignKey('user.username'))
    receiver_username = Column(String, ForeignKey('user.username'))
    content = Column(String)  # This will store the encrypted content
    timestamp = Column(DateTime, default=datetime.utcnow)
    room_id = Column(Integer, ForeignKey('room.id'))

    sender = relationship("User", foreign_keys=[sender_username], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_username], back_populates="received_messages")
    room = relationship("Room")

class Friendship(Base):
    __tablename__ = "friendship"
    id = Column(Integer, primary_key=True)
    user_username = Column(String, ForeignKey('user.username'))
    friend_username = Column(String, ForeignKey('user.username'))

    user = relationship("User", foreign_keys=[user_username], back_populates="friends")
    friend = relationship("User", foreign_keys=[friend_username])

class FriendRequest(Base):
    __tablename__ = "friend_request"
    id = Column(Integer, primary_key=True)
    sender_username = Column(String, ForeignKey('user.username'))
    receiver_username = Column(String, ForeignKey('user.username'))
    accepted = Column(Boolean, default=False)

    sender = relationship("User", foreign_keys=[sender_username], back_populates="sent_requests")
    receiver = relationship("User", foreign_keys=[receiver_username], back_populates="received_requests")

# stateful counter for room IDs
class Counter:
    def __init__(self):
        self.counter = 0

    def get(self):
        self.counter += 1
        return self.counter
