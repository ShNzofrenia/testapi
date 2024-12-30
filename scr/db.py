import sqlite3
import os
import nacl.pwhash
import nacl.utils
from nacl.exceptions import CryptoError

DATABASE = "my_database.db"

def open_db():
    """Открывает соединение с базой данных SQLite."""
    conn = sqlite3.connect(DATABASE)
    return conn


def create_tables():
    """Создает необходимые таблицы в базе данных."""
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
        conn.commit()
