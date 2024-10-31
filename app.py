from flask import Flask, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from routes.login import login_bp
from routes.users import users_bp
from user import User
import os
from dotenv import load_dotenv
from flask_cors import CORS
import jwt
from db import db
from routes.wallet import wallet_bp

# Cargar las variables de entorno desde un archivo .env
load_dotenv()

app = Flask(__name__)
CORS(app)  # Permitir peticiones desde un origen distinto (React, por ejemplo)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# Configurar el gestor de inicio de sesión
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login.login"  # Redirigir a la página de inicio de sesión si el usuario no está autenticado

@login_manager.user_loader
def load_user(username):
    return User.get_user_by_username(username)  # Función para cargar el usuario en la sesión

# Registrar los blueprints para organizar las rutas de la aplicación
app.register_blueprint(login_bp)  # Rutas de inicio de sesión
app.register_blueprint(users_bp)  # Rutas de usuarios
app.register_blueprint(wallet_bp)  # Rutas de wallet

# Ruta para obtener los datos del usuario a partir del token
@app.route('/api/user', methods=['GET'])
def get_user_data():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Token no proporcionado"}), 401

    try:
        # Extraer el token de la cabecera
        token = auth_header.split(" ")[1]
        # Decodificar el token
        decoded = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        username = decoded['username']
        # Obtener los datos del usuario de la base de datos
        user = db.usuarios.find_one({"username": username}, {"_id": 0, "username": 1, "role": 1})
        if user:
            return jsonify(user), 200
        else:
            return jsonify({"message": "Usuario no encontrado"}), 404
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido"}), 401

# Ruta principal de la aplicación
@app.route('/')
def home():
    return "inicio"  # Página de inicio de la aplicación

# Iniciar la aplicación Flask
if __name__ == '__main__':
    app.run(debug=True)
