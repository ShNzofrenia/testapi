import jwt
from datetime import datetime, timedelta
from scr.regex import is_valid_jwt


SECRET_KEY = "your_secret_key"  # Замените на свой секретный ключ


def create_jwt(username):
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Токен действителен в течении 1 часа
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def validate_jwt(token):
    if not is_valid_jwt(token):
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload['username']
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")