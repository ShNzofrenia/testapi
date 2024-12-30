from flask import Flask, request, jsonify, make_response
import jwt
from functools import wraps
from datetime import datetime, timedelta
import re
from scr.db import open_db, close_db, create_tables, add_user, validate_user, add_to_cart, get_cart, delete_user, update_user_password, hash_password
from scr.regex import is_valid_login, is_valid_password, is_valid_jwt
from scr.token import create_jwt, validate_jwt
import os

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY")
app.config['SECRET_KEY'] = SECRET_KEY

def protected(func):
   @wraps(func)
   def wrapper(*args, **kwargs):
     auth_header = request.headers.get("Authorization")
     if auth_header and auth_header.startswith("Bearer "):
          token = auth_header.split(" ", 1)[1]
          username = validate_jwt(token)
          if username:
              return func(*args, **kwargs, username=username)
          else:
             return make_response(jsonify({"message": "Invalid token"}), 401)
     else:
        return make_response(jsonify({"message": "Missing token"}), 401)
   return wrapper


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return make_response(jsonify({"message": "Missing username or password"}), 400)
    if not is_valid_login(username) or not is_valid_password(password):
        return make_response(jsonify({"message": "Invalid username or password"}), 401)
    conn = open_db()
    if validate_user(conn, username, password):
        token = create_jwt(username)
        close_db(conn)
        return make_response(jsonify({"token": token}), 200)
    else:
        close_db(conn)
        return make_response(jsonify({"message": "Invalid username or password"}), 401)

@app.route('/validate-token', methods=['GET'])
@protected
def validate_token(username):
        return make_response(jsonify({"message": f"Token is valid for user: {username}"}), 200)

@app.route('/add-to-cart', methods=['POST'])
@protected
def add_to_cart_route(username):
    data = request.get_json()
    item_name = data.get("item_name")
    quantity = data.get("quantity")
    if not item_name or not quantity:
        return make_response(jsonify({"message": "Invalid input data"}), 400)
    conn = open_db()
    if add_to_cart(conn, username, item_name, int(quantity)):
        close_db(conn)
        return make_response(jsonify({"message": "Item added to cart"}), 200)
    else:
         close_db(conn)
         return make_response(jsonify({"message": "Failed to add item"}), 400)


@app.route('/delete-user', methods=['DELETE'])
@protected
def delete_user_route(username):
    conn = open_db()
    if delete_user(conn, username):
      close_db(conn)
      return make_response(jsonify({"message": "User deleted successfully"}), 200)
    else:
      close_db(conn)
      return make_response(jsonify({"message": "User deletion failed"}), 400)

@app.route('/update-password', methods=['PUT'])
@protected
def update_password_route(username):
    data = request.get_json()
    new_password = data.get("new_password")
    if not new_password:
        return make_response(jsonify({"message": "Invalid input data"}), 400)
    if not is_valid_password(new_password):
            return make_response(jsonify({"message": "Invalid password"}), 401)
    conn = open_db()
    if update_user_password(conn, username, new_password):
        close_db(conn)
        return make_response(jsonify({"message": "Password updated successfully"}), 200)
    else:
        close_db(conn)
        return make_response(jsonify({"message": "Password update failed"}), 400)

@app.route('/add-user', methods=['POST'])
def add_user_route():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return make_response(jsonify({"message": "Missing username or password"}), 400)
    if not is_valid_login(username) or not is_valid_password(password):
        return make_response(jsonify({"message": "Invalid username or password"}), 401)
    conn = open_db()
    if add_user(conn, username, password):
        close_db(conn)
        return make_response(jsonify({"message": "User created successfully"}), 201)
    else:
         close_db(conn)
         return make_response(jsonify({"message": "User creation failed"}), 400)

@app.route('/get-cart', methods=['POST'])
@protected
def get_cart_route(username):
    conn = open_db()
    cart = get_cart(conn, username)
    close_db(conn)
    return make_response(jsonify({"cart": cart}), 200)

@app.route('/db-info', methods=['GET'])
def get_db_info():
       conn = open_db()
       cursor = conn.cursor()
       cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
       tables = [row[0] for row in cursor.fetchall()]
       table_info = {}
       for table in tables:
          cursor.execute(f"PRAGMA table_info({table});")
          columns = [{"name": row[1], "type": row[2]} for row in cursor.fetchall()]
          table_info[table] = columns
       close_db(conn)
       return make_response(jsonify(table_info), 200)