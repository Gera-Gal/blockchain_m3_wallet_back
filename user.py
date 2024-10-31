# user.py
from flask_login import UserMixin
from db import db

class User(UserMixin):
    def __init__(self, username, password, role='user'):
        self.username = username
        self.password = password
        self.role = role
    
    def get_id(self):
        return self.username

    @staticmethod
    def get_user_by_username(username):
        user_data = db.usuarios.find_one({"username": username})
        if user_data:
            return User(
                username=user_data['username'], 
                password=user_data['password'], 
                role=user_data.get('role', 'user')
            )
        return None