'''
app.py contains all of the server application
this is where you'll find all of the get/post request handlers
the socket event handlers are inside of socket_routes.py
'''

import base64
import os
import secrets
from functools import wraps

import bcrypt
import db
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   session, url_for)
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex()
socketio = SocketIO(app)

import socket_routes


@app.route("/")
def index():
    return render_template("index.jinja")

@app.route("/login")
def login():    
    return render_template("login.jinja")

@app.route("/login/user", methods=["POST"])
def login_user():
    if not request.is_json:
        abort(404)

    username = request.json.get("username")
    password = request.json.get("password")
    user = db.get_user(username)
    if user is None:
        return "Error: User does not exist!"

    if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        # Generate key from password and user's stored salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=user.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        session['username'] = username
        session['key'] = key.decode('utf-8')
        return redirect(url_for('home'))
    return "Error: Password does not match!"

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/signup")
def signup():
    return render_template("signup.jinja")

@app.route("/signup/user", methods=["POST"])
def signup_user():
    if not request.is_json:
        abort(404)
    username = request.json.get("username")
    password = request.json.get("password")

    if db.get_user(username) is None:
        db.insert_user(username, password)
        return login_user()
    return "Error: User already exists!"

@app.errorhandler(404)
def page_not_found(_):
    return render_template('404.jinja'), 404

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/home")
@login_required
def home():
    username = session.get('username')
    friends = db.get_friends(username)
    received_requests = db.get_received_friend_requests(username)
    sent_requests = db.get_sent_friend_requests(username)
    return render_template("home.jinja", username=username, friends=friends, received_requests=received_requests, sent_requests=sent_requests)

@app.route("/add_friend", methods=["POST"])
@login_required
def add_friend():
    if not request.is_json:
        abort(404)
    sender_username = session.get("username")
    receiver_username = request.json.get("receiver_username")
    result = db.add_friend(sender_username, receiver_username)
    return jsonify(result)

@app.route("/respond_friend_request", methods=["POST"])
@login_required
def respond_friend_request():
    if not request.is_json:
        abort(404)
    request_id = request.json.get("request_id")
    accept = request.json.get("accept")
    result = db.respond_to_friend_request(request_id, accept)
    return jsonify(result)

if __name__ == '__main__':
    socketio.run(app)
