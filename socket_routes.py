'''
socket_routes
file containing all the routes related to socket.io
'''


import db
from app import socketio
from flask import request, session
from flask_socketio import emit, join_room, leave_room
from models import Room

room = Room()

@socketio.on('connect')
def connect():
    username = session.get("username")
    room_id = session.get("room_id")
    if room_id and username:
        join_room(room_id)
        emit("incoming", {"msg": f"{username} has connected", "type": "status", "color": "green"}, room=room_id)

@socketio.on('disconnect')
def disconnect():
    username = session.get("username")
    room_id = session.get("room_id")
    if room_id and username:
        emit("incoming", {"msg": f"{username} has disconnected", "type": "status", "color": "red"}, room=room_id)

@socketio.on("send")
def send(data):
    username = session.get("username")
    key = session.get('key')  # Retrieve encryption key from session
    message = data["message"]
    room_id = data["room_id"]
    encrypted_message = db.encrypt_message(key, message)  # Encrypt using the derived key
    db.save_message(username, data['receiver_username'], encrypted_message, room_id)
    emit("incoming", {"msg": f"{username}: {encrypted_message}", "type": "message"}, room=room_id)

@socketio.on("join")
def join(data):
    sender_name = session.get("username")
    receiver_name = data["receiver_name"]
    receiver = db.get_user(receiver_name)
    if not receiver:
        emit("error", {"msg": "Unknown receiver!"})
        return
    room_id = room.get_room_id(receiver_name)
    if room_id:
        room.join_room(sender_name, room_id)
        join_room(room_id)
        emit("incoming", {"msg": f"{sender_name} has joined the room with {receiver_name}.", "type": "status", "color": "green"}, room=room_id)
    else:
        room_id = room.create_room(sender_name, receiver_name)
        join_room(room_id)
        emit("incoming", {"msg": f"{sender_name} has joined a new room with {receiver_name}.", "type": "status", "color": "green"}, room=room_id)

@socketio.on("leave")
def leave(data):
    username = session.get("username")
    room_id = data["room_id"]
    leave_room(room_id)
    room.leave_room(username)
    emit("incoming", {"msg": f"{username} has left the room.", "type": "status", "color": "red"}, room=room_id)

@socketio.on("get_history")
def get_history(data):
    room_id = data["room_id"]
    key = session.get('key')  # Retrieve encryption key from session
    messages = db.get_messages_by_room_id(room_id)
    decrypted_messages = [{'username': m[0], 'message': db.decrypt_message(key, m[2]), 'timestamp': m[3].strftime('%Y-%m-%d %H:%M:%S')} for m in messages]
    emit("history", decrypted_messages, room=room_id)
