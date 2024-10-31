# db.py
from pymongo import MongoClient
from config import Config

client = MongoClient(Config.MONGODB_URI)
db = client.get_database()  # Obtiene la base de datos 'blockchain' especificada en la URI