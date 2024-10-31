from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
import requests
import os
import jwt
import json
from db import db

wallet_bp = Blueprint('wallet', __name__)

# Ruta para crear una nueva wallet
@wallet_bp.route('/api/wallet', methods=['POST'])
def create_wallet():
    # Obtener el token JWT del encabezado Authorization
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Token no proporcionado"}), 401

    try:
        # Extraer el token del encabezado
        token = auth_header.split(" ")[1]
        # Decodificar el token
        decoded = jwt.decode(token, os.getenv('SECRET_KEY', 'default_secret_key'), algorithms=["HS256"])
        username = decoded.get('username')
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido"}), 401

    if not username:
        return jsonify({"message": "Usuario no encontrado"}), 400

    # Verificar si el usuario ya tiene una wallet
    existing_wallet = db.wallets.find_one({"username": username})
    if existing_wallet:
        return jsonify({"message": "El usuario ya tiene una wallet", "wallet": existing_wallet['wallet']}), 200

    # Configurar los encabezados para la API de Tatum
    headers = {
        "accept": "application/json",
        "x-api-key": os.getenv('TATUM_API_KEY')  # Asegúrate de configurar esta variable de entorno
    }

    # Primera llamada para obtener xpub y mnemonic
    response = requests.get("https://api.tatum.io/v3/polygon/wallet", headers=headers)
    if response.status_code != 200:
        return jsonify({"message": "Error al generar la wallet"}), 500
    wallet_data = response.json()

    xpub = wallet_data['xpub']
    mnemonic = wallet_data['mnemonic']

    # Segunda llamada para obtener la dirección de la billetera
    response_address = requests.get(f"https://api.tatum.io/v3/polygon/address/{xpub}/0", headers=headers)
    if response_address.status_code != 200:
        return jsonify({"message": "Error al obtener la dirección de la wallet"}), 500
    address_data = response_address.json()

    # Tercera llamada para obtener la clave privada
    payload = {
        "index": 0,
        "mnemonic": mnemonic
    }
    response_priv_key = requests.post("https://api.tatum.io/v3/polygon/wallet/priv", json=payload, headers=headers)
    if response_priv_key.status_code != 200:
        return jsonify({"message": "Error al obtener la clave privada"}), 500
    priv_key_data = response_priv_key.json()

    # Crear la wallet
    wallet = {
        "xpub": xpub,
        "mnemonic": mnemonic,
        "address": address_data['address'],
        "private_key": priv_key_data['key']
    }

    # Guardar la wallet en la base de datos MongoDB, en la colección 'wallets'
    db.wallets.insert_one({
        "username": username,
        "wallet": wallet
    })

    return jsonify({"message": "Wallet generada con éxito", "wallet": wallet}), 201


# Ruta para consultar la wallet existente
@wallet_bp.route('/api/wallet', methods=['GET'])
def get_wallet():
    # Obtener el token JWT del encabezado Authorization
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Token no proporcionado"}), 401

    try:
        # Extraer el token del encabezado
        token = auth_header.split(" ")[1]
        # Decodificar el token
        decoded = jwt.decode(token, os.getenv('SECRET_KEY', 'default_secret_key'), algorithms=["HS256"])
        username = decoded.get('username')
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido"}), 401

    if not username:
        return jsonify({"message": "Usuario no encontrado"}), 400

    # Buscar la wallet del usuario
    existing_wallet = db.wallets.find_one({"username": username})
    if existing_wallet:
        return jsonify({"wallet": existing_wallet['wallet']}), 200
    else:
        return jsonify({"message": "El usuario no tiene una wallet"}), 404


# Ruta para consultar los saldos de la wallet y guardarlos en la base de datos
@wallet_bp.route('/api/wallet/balances', methods=['GET'])
def get_wallet_balances():
    # Obtener el token JWT del encabezado Authorization
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Token no proporcionado"}), 401

    try:
        # Extraer el token del encabezado
        token = auth_header.split(" ")[1]
        # Decodificar el token
        decoded = jwt.decode(token, os.getenv('SECRET_KEY', 'default_secret_key'), algorithms=["HS256"])
        username = decoded.get('username')
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido"}), 401

    if not username:
        return jsonify({"message": "Usuario no encontrado"}), 400

    # Buscar la wallet del usuario
    existing_wallet = db.wallets.find_one({"username": username})
    if not existing_wallet:
        return jsonify({"message": "El usuario no tiene una wallet"}), 404

    wallet_address = existing_wallet['wallet']['address']

    # Consultar en la base de datos MongoDB, en la colección 'saldos'
    user_balances = db.saldos.find_one(
        {"username": username}  # Filtro para encontrar el documento existente
    )
    if not user_balances:
        balance_data = fetch_and_save_balances(wallet_address, username)
        return jsonify({"message": "Saldos guardados con éxito", "balances": balance_data["result"]}), 200

    return jsonify({"message": "Saldos guardados con éxito", "balances": user_balances["balances"]}), 200


@wallet_bp.route('/api/wallet/update/balances', methods=['GET'])
def update_and_get_wallet_balances():
    # Obtener el token JWT del encabezado Authorization
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Token no proporcionado"}), 401

    try:
        # Extraer el token del encabezado
        token = auth_header.split(" ")[1]
        # Decodificar el token
        decoded = jwt.decode(token, os.getenv('SECRET_KEY', 'default_secret_key'), algorithms=["HS256"])
        username = decoded.get('username')
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido"}), 401

    if not username:
        return jsonify({"message": "Usuario no encontrado"}), 400

    # Buscar la wallet del usuario
    existing_wallet = db.wallets.find_one({"username": username})
    if not existing_wallet:
        return jsonify({"message": "El usuario no tiene una wallet"}), 404

    wallet_address = existing_wallet['wallet']['address']

    balance_data = fetch_and_save_balances(wallet_address, username)

    return jsonify({"message": "Saldos guardados con éxito", "balances": balance_data['result']}), 200

def fetch_and_save_balances(wallet_address, username):
    # Llamada a la API de Tatum para obtener los saldos de la wallet
    url = f"https://api.tatum.io/v4/data/wallet/balances?chain=polygon&addresses={wallet_address}"
    headers = {
        "accept": "application/json",
        "x-api-key": os.getenv('TATUM_API_KEY')
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return jsonify({"message": "Error al consultar los saldos: "}), 500

    balance_data = response.json()

    for item in balance_data["result"]:
        if item["type"] == "nft" and "metadataURI" in item:
            if("https" in item["metadataURI"]):
                print(item["metadataURI"])
                item["metadataURI"] = item["metadataURI"].replace('ipfs.io','gateway.pinata.cloud')
                url = item["metadataURI"]
                response = requests.get(url, headers=headers)
                if response.status_code != 200:
                    print(response.text)
                    return jsonify({"message": "Error al consultar metadata de NFT: "}), 500
                item["metadata"] = response.json()
            else:
                item["metadataURI"] = ""
                item["metadata"] = {
                    "image": "https://upload.wikimedia.org/wikipedia/commons/thumb/a/ac/No_image_available.svg/800px-No_image_available.svg.png",
                    "description": "N/A",
                    "name": "N/A"
                }
        elif "tokenAddress" in item:
            token_address = item["tokenAddress"]
            url = f"https://api.tatum.io/v4/data/tokens?chain=polygon&tokenAddress={token_address}"
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print(response.text)
                return jsonify({"message": "Error al consultar detalles de token fungible: "}), 500
            item["details"] = response.json()

    # Guardar o actualizar los saldos en la base de datos MongoDB, en la colección 'saldos'
    db.saldos.update_one(
        {"username": username},  # Filtro para encontrar el documento existente
        {
            "$set": {
                "wallet_address": wallet_address,
                "balances": balance_data["result"]
            }
        },
        upsert=True  # Si no existe el documento, lo crea
    )

    return balance_data

# Nueva ruta para transferir tokens
@wallet_bp.route('/api/transferir', methods=['POST'])
def transferir():
    if request.method == 'POST':
        # Obtener los datos del JSON enviado desde el frontend
        data = request.get_json()

        private_key = data.get('private_key')
        contract_address = data.get('contract_address')
        to_address = data.get('to_address')
        amount = data.get('amount')
        token_id = data.get('token_id')
        currency = data.get('currency')  # Para transferencias nativas

        # Si es una transferencia de token nativo, omitimos el contract_address
        if not private_key or not to_address:
            return jsonify({"message": "Todos los campos son obligatorios"}), 400

        # Si es una transferencia de token nativo (MATIC)
        if currency == 'MATIC':
            url = "https://api.tatum.io/v3/polygon/transaction"
            data = {
                "fromPrivateKey": private_key,
                "to": to_address,
                "amount": amount,
                "currency": currency
            }
        elif not amount:
            # Si es una transferencia de token ERC721
            print(token_id)
            if not token_id:
                return jsonify({"message": "Todos los campos son obligatorios"}), 400

            url = "https://api.tatum.io/v3/nft/transaction"
            data = {
                "chain": "MATIC",
                "to": to_address,
                "tokenId": token_id,
                "contractAddress": contract_address,
                "fromPrivateKey": private_key
            }
        else:
            print(to_address, amount, contract_address, private_key)
            url = "https://api.tatum.io/v3/blockchain/token/transaction"
            data = {
                "chain": "MATIC",
                "to": to_address,
                "amount": amount,
                "contractAddress": contract_address,
                "digits": 18,
                "fromPrivateKey": private_key
            }

        headers = {
            "Content-Type": "application/json",
            "x-api-key": os.getenv('TATUM_API_KEY')
        }

        try:
            response = requests.post(url, headers=headers, data=json.dumps(data))
            response.raise_for_status()  # Lanza una excepción si ocurre un error HTTP
            result = response.json()
            return jsonify({"message": "Transacción exitosa", "result": result}), 200
        except requests.exceptions.HTTPError as http_err:
            return jsonify({"message": f"HTTP error occurred: {http_err}", "error": response.text}), 500
        except Exception as err:
            return jsonify({"message": f"An error occurred: {err}"}), 500
