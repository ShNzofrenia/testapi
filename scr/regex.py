import re

def is_valid_login(login):
    login_regex = r"^[a-zA-Z0-9_]{3,20}$"
    return bool(re.match(login_regex, login))


def is_valid_password(password):
    password_regex = r"^[a-zA-Z0-9@#%*!?]{8,32}$"
    return bool(re.match(password_regex, password))

def is_valid_jwt(token):
   jwt_regex = r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
   return bool(re.match(jwt_regex, token))