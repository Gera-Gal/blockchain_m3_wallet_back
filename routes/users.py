from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from pymongo import MongoClient
from config import Config
from decorators import admin_required

users_bp = Blueprint('users', __name__)

client = MongoClient(Config.MONGODB_URI)
db = client['blockchain']
users_collection = db.get_collection('usuarios')
wallets_collection = db.get_collection('wallets')

@users_bp.route('/users')
@login_required
@admin_required
def users():
    usuarios = users_collection.find({"role": "user"})
    users_data = []
    for usuario in usuarios:
        wallet = wallets_collection.find_one({"username": usuario["username"]})
        wallet_address = wallet["wallet"]["address"] if wallet else "No wallet found"
        users_data.append({
            "username": usuario["username"],
            "wallet_address": wallet_address
        })
    return render_template('users.html', users=users_data)

# Nueva ruta API para ser consumida por React (devolver usuarios en formato JSON)
@users_bp.route('/api/users', methods=['GET'])
@login_required
def get_users():
    usuarios = users_collection.find({"role": "user"})
    users_data = []
    for usuario in usuarios:
        users_data.append({
            "username": usuario["username"]
        })
    return jsonify(users_data)