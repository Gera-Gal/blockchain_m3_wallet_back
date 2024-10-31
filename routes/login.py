from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required
from werkzeug.security import check_password_hash
from user import User
from db import db
import jwt
import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash

login_bp = Blueprint('login', __name__)

# Ruta API para el inicio de sesión (para ser usada por React)
@login_bp.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.get_user_by_username(username)

    if user and check_password_hash(user.password, password):
        # Generar token JWT
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # Token expira en 24 horas
        }, os.getenv('SECRET_KEY', 'default_secret_key'), algorithm='HS256')

        # Guardar el token en la colección del usuario
        db.usuarios.update_one({'username': username}, {'$set': {'token': token}})

        # Iniciar sesión del usuario (Flask-Login)
        login_user(user)

        return jsonify({"message": "Inicio de sesión exitoso", "success": True, "token": token}), 200
    else:
        return jsonify({"message": "Usuario o contraseña incorrectos", "success": False}), 401

# Ruta API para el registro de usuarios (para ser usada por React)
@login_bp.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    hashed_password = generate_password_hash(password)

    db.usuarios.insert_one({
        'username': username,
        'password': hashed_password,
        'role': 'user',
        'token': None  # Inicialmente sin token
    })

    return jsonify({"message": "Registro exitoso, ahora puedes iniciar sesión"}), 201

# Ruta API para el cierre de sesión (para ser usada por React)
@login_bp.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({"message": "Sesión cerrada correctamente"}), 200