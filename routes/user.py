from datetime import datetime, timedelta
import os
import time
from flask import Blueprint, request, jsonify
from sqlalchemy import Date
from models.models import db,User,LogConnexion
import bcrypt
import traceback
import jwt
from user_agents import parse
from auth_middleware import token_required


# Instances du schema utilisateur
#utilisateur_schema = UtilisateurSchema()
#utilisateur_schema_many = UtilisateurSchema(many=True)

# Créer un groupe de routes pour utilisateur
user_routes = Blueprint('user_routes', __name__)

# Create user
@user_routes.route('/user/register', methods=['POST'])
def create_user():
    try:
        data = request.json
        for key, value in data.items():
            if value is None or value == "":
                return jsonify({"error": f"Value for '{key}' is missed"}), 400
        prenom = data.get('prenom')
        nom = data.get('nom')
        email = data.get('email')
        password = bcrypt.hashpw(data.get('password').encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        role = data.get('role')
        deletable = data.get('deletable')
        age = data.get('age')
        genre = data.get('genre')
        new_user = User(nom=nom, prenom=prenom,email=email,password=password, role=role,genre=genre,age=age,deletable=deletable)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Success"}), 201 
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error" : "An error occurred when creating the user", "details": str(e)}), 500

# Login
@user_routes.route('/user/login', methods=['POST'])
def login_utilisateur():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "error"}), 400

    user = User.query.filter_by(email=email).first()
    print(user)
    if not user:
        return jsonify({"error": "not found"}), 404

    passv = user.password
    if not bcrypt.checkpw(password.encode('utf-8'), passv.encode('utf-8')):
        user_agent = request.headers.get('User-Agent')
        user_agent = parse(user_agent)
        datecon = datetime.now()
        ip = request.remote_addr
        user_id = user.id
        resultat = "Connexion échouée"
        new_log = LogConnexion(
            date_connexion=datecon,
            adresse_Ip=ip,
            resultat=resultat,
            user_id=user_id,
            browser=user_agent.browser.family,
            browser_version=user_agent.browser.version_string ,
            os=user_agent.os.family ,
            os_version=user_agent.os.version_string, 
            device=user_agent.device.family,
            is_mobile=user_agent.is_mobile ,
            is_tablet=user_agent.is_tablet, 
            is_pc=user_agent.is_pc,
            is_bot=user_agent.is_bot)  
          
        db.session.add(new_log)
        db.session.commit()
        return jsonify({"error": "error"}), 400
    

    payload = {
        "user_id": user.id,
        "role": user.role,
        "exp": int(time.time()) + 86400 
    }

    token = jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm="HS256")
    islogin = True
    
    
    user_agent = request.headers.get('User-Agent')
    user_agent = parse(user_agent)

    datecon = datetime.now()
    ip = request.remote_addr
    user_id = user.id
    resultat = "Connexion réussie"
    new_log = LogConnexion(
        date_connexion=datecon,
        adresse_Ip=ip,
        resultat=resultat,
        user_id=user_id,
        browser=user_agent.browser.family,
        browser_version=user_agent.browser.version_string ,
        os=user_agent.os.family ,
        os_version=user_agent.os.version_string, 
        device=user_agent.device.family,
        is_mobile=user_agent.is_mobile ,
        is_tablet=user_agent.is_tablet, 
        is_pc=user_agent.is_pc,
        is_bot=user_agent.is_bot)    
    db.session.add(new_log)
    db.session.commit()

    return jsonify({
        "message": "Success",
        "user": {
            "id": user.id,
            "nom": user.nom,
            "prenom": user.prenom,
            "email": user.email,
            "genre": user.genre,
            "age" : user.age,
            "role": user.role
        },
        "token" :token,
        "islogin":islogin
    }), 200

# Logout
@user_routes.route('/user/logout', methods=['POST'])
@token_required
def logout_utilisateur():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Token is missing"}), 401

    try:
        # Extraire le token en supprimant "Bearer "
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1] 
            print(token) # Récupère la partie après "Bearer "
        else:
            token = auth_header  # Si pas de préfixe Bearer
            print(token)

        payload = jwt.decode(token,os.getenv('SECRET_KEY'), algorithms=["HS256"])
        user_id = payload['user_id']
        print(payload)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except IndexError:
        return jsonify({"error": "Invalid Authorization header format"}), 401

    

    user_agent = request.headers.get('User-Agent')
    user_agent = parse(user_agent)

    datedecon = datetime.now()
    ip = request.remote_addr
    user_id = user_id
    resultat = "Déconnexion réussie"
    new_log = LogConnexion(
        date_connexion=datedecon,
        adresse_Ip=ip,
        resultat=resultat,
        user_id=user_id,
        browser=user_agent.browser.family,
        browser_version=user_agent.browser.version_string ,
        os=user_agent.os.family ,
        os_version=user_agent.os.version_string, 
        device=user_agent.device.family,
        is_mobile=user_agent.is_mobile ,
        is_tablet=user_agent.is_tablet, 
        is_pc=user_agent.is_pc,
        is_bot=user_agent.is_bot)      
    db.session.add(new_log)
    db.session.commit()
    return jsonify({"message": "success"}), 200

