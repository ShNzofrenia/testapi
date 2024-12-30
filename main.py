from flask import Flask, request, jsonify, make_response
import sqlite3
import os
import jwt
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = "my_database.db"
SECRET_KEY = "your_secret_key"  # Замените на свой секретный ключ


def open_db():
    conn = sqlite3.connect(DATABASE)
    return conn


def create_tables():
    with open_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE,
                            password TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS cart (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            item_name TEXT,
                            quantity INTEGER,
                            FOREIGN KEY (user_id) REFERENCES users (id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS products (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT UNIQUE,
                            price REAL)''')
        conn.commit()


def create_jwt(username):
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Токен действителен в течении 1 часа
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def validate_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload['username']
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None

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
    data = request.json
    username = data.get('username')
    password = data.get('password')

    with open_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            token = create_jwt(username)
            return jsonify({"token": token}), 200
        else:
            return jsonify({"message": "Invalid username or password"}), 401

@app.route('/validate-token', methods=['GET'])
@protected
def validate_token(username):
    return make_response(jsonify({"message": f"Token is valid for user: {username}"}), 200)

@app.route('/add-зкщ', methods=['POST'])
@protected
def add_to_cart(username):
    data = request.json
    item_name = data.get('item_name')
    quantity = data.get('quantity')

    if  quantity > 0:
        with open_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"message": "User not found"}), 404
            cursor.execute('INSERT INTO cart (user_id, item_name, quantity) VALUES (?, ?, ?)',
                           (user[0], item_name, quantity))
            conn.commit()
            return jsonify({"message": "Item added to cart"}), 200

    return jsonify({"message": "Failed to add item"}), 400


@app.route('/remove-from-product', methods=['POST'])
def remove_product():
    data = request.get_json()
    name = data.get("name")
    price = data.get("price")
    if not name or not price:
        return make_response(jsonify({"message": "Missing product name or price"}), 400)

    with open_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM products where name=? and price=?', (name, price))
        conn.commit()
        return jsonify({"message": "Product removed successfully"}), 201



@app.route('/add-user', methods=['POST'])
def add_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    hashed_password = generate_password_hash(password)

    try:
        with open_db() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            return jsonify({"message": "User created successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 400


@app.route('/delete-user', methods=['DELETE'])
@protected
def delete_user(username):
     with open_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
           return jsonify({"message": "User not found"}), 404
        cursor.execute('DELETE FROM users WHERE id = ?', (user[0],))
        conn.commit()
        return jsonify({"message": "User deleted successfully"}), 200


@app.route('/update-password', methods=['PUT'])
@protected
def update_password(username):
    data = request.json
    new_password = data.get('new_password')

    hashed_password = generate_password_hash(new_password)
    with open_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user[0]))
        conn.commit()
        return jsonify({"message": "Password updated successfully"}), 200

@app.route('/get-cart', methods=['POST'])
@protected
def get_cart(username):
   with open_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
             return jsonify({"message": "User not found"}), 404
        cursor.execute('SELECT item_name, quantity FROM cart WHERE user_id = ?', (user[0],))
        cart_items = cursor.fetchall()
        if cart_items:
            return jsonify([{"item_name": item[0], "quantity": item[1]} for item in cart_items]), 200
        else:
            return jsonify({"message": "Cart is empty"}), 200
@app.route('/get-products', methods=['GET'])
def get_products():
       with open_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT name, price FROM products')
        products = cursor.fetchall()
        if products:
           return jsonify([{"name": item[0], "price": item[1]} for item in products]), 200
        else:
             return jsonify({"message": "Product list is empty"}), 200


if __name__ == '__main__':
    create_tables()  # Создаем таблицы при запуске приложения
    app.run(debug=True)