from datetime import date, datetime, timedelta
import os
import time
from flask import Blueprint, request, jsonify
from sqlalchemy import Date, and_, func
from models.models import db,User,LogConnexion,MethodeAnalyse,UserActivite
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
        age = data.get('age')
        genre = data.get('genre')
        new_user = User(nom=nom, prenom=prenom,email=email,password=password, role=role,genre=genre,age=age)
        db.session.add(new_user)
        db.session.flush()  

        date_ac = datetime.now()
        new_activity = UserActivite(action="L'utilisateur s'est inscrit",date_action=date_ac,statut=True,user_id= new_user.id)
        db.session.add(new_activity)

        db.session.commit()

        return jsonify({"message": "Success"}), 201 
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error" : "An error occurred when creating the user", "details": str(e)}), 500

# Add user
@user_routes.route('/user/add', methods=['POST'])
@token_required
def add_user():
    try:
        data = request.json
        for key, value in data.items():
            if value is None or value == "":
                return jsonify({"error": f"Value for '{key}' is missed"}), 400
        
        user = data.get('user')
        password = bcrypt.hashpw('User2025'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        prenom = user.get('prenom')
        nom =user.get('nom')
        email = user.get('email')
        role = user.get('role')
        isActive = True if user.get('statut') == "Actif" else False 
        connected = False
        inscription = user.get('dateCreation')
        age = user.get('age')
        genre = 'M' if user.get('genre') == "Homme" else 'F'   
        new_user = User(nom=nom, prenom=prenom,email=email,password=password, role=role,genre=genre,age=age,isActive=isActive,connected=connected,inscription=inscription)

        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "success"}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error" : "An error occurred when adding  user", "details": str(e)}), 500
# update user
@user_routes.route('/user/update/<id>', methods=['PUT'])
@token_required
def update_user(id):
    try:
        user = User.query.get(id)
        data = request.json
        for key, value in data.items():
            if value is None or value == "":
                return jsonify({"error": f"Value for '{key}' is missed"}), 400
        
        new_user = data.get('user')
        user.prenom = new_user.get('prenom')
        user.nom = new_user.get('nom')
        user.email = new_user.get('email')
        user.role = new_user.get('role')
        user.age = new_user.get('age')
        user.genre = 'M' if new_user.get('genre') == "Homme" else 'F'        
        db.session.commit()

        return jsonify({"message": "success"}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error" : "An error occurred when updating the user", "details": str(e)}), 500


# Delete user
@user_routes.route('/user/delete/<id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.session.delete(user)   
    db.session.commit()       

    return jsonify({"message": "success"}), 200



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

        date_ac = datetime.now()
        new_activity = UserActivite(action="L'utilisateur tente de se connecté ",date_action=date_ac,statut=False,user_id= user_id)
        db.session.add(new_activity)

        db.session.commit()
        return jsonify({"error": "error"}), 400
    
    if user.isActive == True:
        payload = {
            "user_id": user.id,
            "role": user.role,
            "exp": int(time.time()) + 86400 
        }

        token = jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm="HS256")
        islogin = True
        
        
        user_agent = request.headers.get('User-Agent')
        user_agent = parse(user_agent)

        datecon = date.today().strftime("%Y-%m-%d")
        ip = request.remote_addr
        user_id = user.id
        resultat = "Connexion réussie"
        user.connected = True
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

        date_ac = datetime.now()
        new_activity = UserActivite(action="L'utilisateur s'est connecté avec succès ",date_action=date_ac,statut=True,user_id= user_id)
        db.session.add(new_activity)
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
                "role": user.role,
                "isActive": user.isActive
            },
            "token" :token,
            "islogin":islogin
        }), 200
    else:
        date_ac = datetime.now()
        new_activity = UserActivite(action="L'utilisateur tente de se connecter à son compte suspendu ",date_action=date_ac,statut=False,user_id= user.id)
        db.session.add(new_activity)
        db.session.commit()
        return jsonify({
            "message": "suspended",
            "user": {
                "isActive": user.isActive
            },
        }), 401
    

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
            
        payload = jwt.decode(token,os.getenv('SECRET_KEY'), algorithms=["HS256"])
        user_id = payload['user_id']
        #print(payload)
    except jwt.ExpiredSignatureError:
        date_ac = datetime.now()
        new_activity = UserActivite(action="Erreur Déconnexion token expiré",date_action=date_ac,statut=False,user_id= user_id)
        db.session.add(new_activity)
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        date_ac = datetime.now()
        new_activity = UserActivite(action="Erreur Déconnexion token invalide",date_action=date_ac,statut=False,user_id= user_id)
        db.session.add(new_activity)
        return jsonify({"error": "Invalid token"}), 401
    except IndexError:
        date_ac = datetime.now()
        new_activity = UserActivite(action="Erreur Déconnexion Authorisation invalide",date_action=date_ac,statut=False,user_id= user_id)
        db.session.add(new_activity)
        return jsonify({"error": "Invalid Authorization header format"}), 401

    

    user_agent = request.headers.get('User-Agent')
    user_agent = parse(user_agent)

    datedecon = date.today().strftime("%Y-%m-%d")
    ip = request.remote_addr
    user_id = user_id
    resultat = "Déconnexion réussie"
    user = User.query.where(User.id==user_id).first()
    user.connected = False
    user.last_connexion = datetime.now().strftime("%Y-%m-%d %H:%M")
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

    date_ac = datetime.now()
    new_activity = UserActivite(action="L'utilisateur s'est déconnecté avec succès",date_action=date_ac,statut=True,user_id= user_id)
    db.session.add(new_activity)
    db.session.commit()
    return jsonify({"message": "success"}), 200



#Get users informations
@user_routes.route('user/info',methods=['GET'])
@token_required
def get_user_info():
    try:
        active_users = User.query.where(User.isActive == True).count()
        connected_users = User.query.where(User.connected == True).count()
        block_users = User.query.where(User.isActive == False).count()
        analyse = MethodeAnalyse.query.count()
        chercheurs = User.query.where(User.role == 'Chercheur').count()
        etudiants = User.query.where(User.role == 'Etudiant').count()
        hommes = User.query.where(User.genre == 'M').count()
        femmes = User.query.where(User.genre == 'F').count()


        return jsonify({
            "message":"success",
            "active_users" : active_users,
            "connected_users":connected_users,
            "blocked_users":block_users,
            "analyses":analyse,
            "etudiants":etudiants,
            'chercheurs':chercheurs,
            'femmes' : femmes,
            'hommes' : hommes
        }),200
    
    except Exception as e:
        return jsonify({
            'message': 'error',
            'error': 'Erreur lors de la récupération des infos',
            'message': str(e)
        }), 500

#Get all users
@user_routes.route('/user/all', methods=['GET'])
def get_all_users():
    try:
        users = User.query.order_by(User.inscription.desc()).all()
        
        # Conversion en dictionnaire
        users_list = []
        for user in users:
            users_list.append({
                'id': user.id,
                'prenom':user.prenom,
                'nom': user.nom,
                'email': user.email,
                'genre' : user.genre,
                'age': user.age,
                'role': user.role,
                'isActive': user.isActive,
                'connected':user.connected,
                'inscription': user.inscription,
                'last_connexion':user.last_connexion        
            })
        
        return jsonify({
            'message': 'success',
            'users': users_list,
            'count': len(users_list)
        }), 200
        
    except Exception as e:
        return jsonify({
            'message': 'error',
            'error': 'Erreur lors de la récupération des utilisateurs',
            'message': str(e)
        }), 500


#Get last 10 user
@user_routes.route('/user/latest_user', methods=['GET'])
@token_required
def get_latest_user():
    try:
        users = User.query.order_by(User.inscription.desc()).limit(10).all()
        
        # Conversion en dictionnaire
        users_list = []
        for user in users:
            users_list.append({
                'id': user.id,
                'prenom':user.prenom,
                'nom': user.nom,
                'email': user.email,
                'genre' : user.genre,
                'age': user.age,
                'role': user.role,
                'isActive': user.isActive,        
                
            })
        
        return jsonify({
            'message': 'success',
            'users': users_list,
            'count': len(users_list)
        }), 200
        
    except Exception as e:
        return jsonify({
            'message': 'error',
            'error': 'Erreur lors de la récupération des utilisateurs',
            'message': str(e)
        }), 500



#Get all log
@user_routes.route('/user/log/<int:id>', methods=['GET'])
def get_all_log(id):
    try:
        user_log_data = db.session.query(
            User.id,
            User.role,
            User.prenom,
            User.nom,
            User.email,
            User.isActive,
            LogConnexion.date_connexion,
            LogConnexion.adresse_Ip, 
            LogConnexion.resultat,
            LogConnexion.device,
            LogConnexion.is_mobile,
            LogConnexion.is_bot,
            LogConnexion.is_pc,
            LogConnexion.is_tablet,
            LogConnexion.browser,
            LogConnexion.browser_version
        ).join(LogConnexion, User.id == LogConnexion.user_id).filter(User.id == id).order_by(LogConnexion.date_connexion.desc()).first()

        if not user_log_data:
            return jsonify({
                'message': 'No log data found for user ID {}'.format(id)
            }), 404

        # Convert query result to dictionary for JSON serialization
        user_log_dict = {
            'id': user_log_data.id,
            'prenom': user_log_data.prenom,
            'nom': user_log_data.nom,
            'role':user_log_data.role,
            'isActive':user_log_data.isActive,
            'email': user_log_data.email,
            'date_connexion': user_log_data.date_connexion.isoformat() if user_log_data.date_connexion else None,
            'adresse_ip': user_log_data.adresse_Ip,
            'resultat': user_log_data.resultat,
            'device': user_log_data.device,
            'is_mobile': user_log_data.is_mobile,
            'is_bot': user_log_data.is_bot,
            'is_pc': user_log_data.is_pc,
            'is_tablet': user_log_data.is_tablet,
            'browser': user_log_data.browser,
            'browser_version': user_log_data.browser_version
        }

        return jsonify({
            'message': 'success',
            'user_log': user_log_dict
        }), 200

    except Exception as e:
        return jsonify({
            'message': 'error',
            'error': 'Erreur lors de la récupération des données de connexion',
            'details': str(e)
        }), 500
    

#Get last log
@user_routes.route('/user/latest_log', methods=['GET'])
@token_required
def get_last_log():
    try:
        user_log_data = db.session.query(
        User.id,
        User.prenom,
        User.nom,
        User.email,
        LogConnexion.date_connexion,
        LogConnexion.adresse_Ip,
        LogConnexion.resultat,
        LogConnexion.device,
        LogConnexion.is_mobile,
        LogConnexion.is_bot,
        LogConnexion.is_pc,
        LogConnexion.is_tablet,
        LogConnexion.browser,
        LogConnexion.browser_version
        ).join(LogConnexion).order_by(LogConnexion.date_connexion.desc()).limit(10).all()

        last_log_list = []
        for log in user_log_data:
            last_log_list.append({
                'id': log.id,
                'prenom':log.prenom,
                'nom': log.nom,
                'email': log.email,
                'date_connexion' : log.date_connexion,
                'resultat': log.resultat,
                'mobile':log.is_mobile,
                'device':log.device,
                'bot': log.is_bot,
                'pc':log.is_pc,
                'tablet':log.is_tablet,
                'adresse_Ip':log.adresse_Ip,
                'browser':log.browser,
                'browser_version':log.browser_version
            })
        
        return jsonify({
            'message': 'success',
            'last_log_list': last_log_list,
        }), 200
        
    except Exception as e:
        return jsonify({
            'message': 'error',
            'error': 'Erreur lors de la récupération des utilisateurs',
            'message': str(e)
        }), 500



#Get all user activity
@user_routes.route('user/activity', methods=['GET'])
@token_required
def get_user_activity():
    try:
        user_activity = db.session.query(
        User.id,
        User.prenom,
        User.nom,
        User.email,
        User.isActive,
        UserActivite.date_action,
        UserActivite.action,
        UserActivite.statut
        ).join(UserActivite).order_by(UserActivite.date_action.desc()).all()

        activity_list = []
        for activ in user_activity:
            activity_list.append({
                'id': activ.id,
                'prenom':activ.prenom,
                'nom': activ.nom,
                'email': activ.email,
                'date_action' : activ.date_action,
                'action': activ.action,
                'statut': activ.statut,
                'isActive':activ.isActive
            })
        
        return jsonify({
            'message': 'success',
            'activity_list': activity_list,
        }), 200
        
    except Exception as e:
        return jsonify({
            'message': 'error',
            'error': 'Erreur lors de la récupération des utilisateurs',
            'message': str(e)
        }), 500
    
#Get last user activity
@user_routes.route('user/latest_activity', methods=['GET'])
@token_required
def get_last_user_activity():
    try:
        user_activity = db.session.query(
        User.id,
        User.prenom,
        User.nom,
        User.email,
        UserActivite.date_action,
        UserActivite.action
        ).join(UserActivite).order_by(UserActivite.date_action.desc()).limit(10).all()

        activity_list = []
        for activ in user_activity:
            activity_list.append({
                'id': activ.id,
                'prenom':activ.prenom,
                'nom': activ.nom,
                'email': activ.email,
                'date_action' : activ.date_action,
                'action': activ.action,
            })
        
        return jsonify({
            'message': 'success',
            'latest_activities': activity_list,
        }), 200
        
    except Exception as e:
        return jsonify({
            'message': 'error',
            'error': 'Erreur lors de la récupération des utilisateurs',
            'message': str(e)
        }), 500

#Get register history group by day
@user_routes.route('/user/inscription', methods=['GET'])
@token_required
def getinscriptionevolu():
    try:
        req = db.session.query(User.inscription.label('date'),
            func.count(User.id).label('nombre')).group_by(User.inscription).order_by(User.inscription.asc()).all()
        
        # Conversion en liste de dictionnaires
        inscriptions_data = []
        for row in req:
            inscriptions_data.append({
                'date': row.date.isoformat(),
                'nombre': row.nombre
            })
        
        return jsonify({
            'message': 'success',
            'inscriptions_data': inscriptions_data,
            'total': len(inscriptions_data)
        }), 200
        
    except Exception as e:
        return jsonify({
            'message': 'error',
            'error': 'Erreur lors de la récupération des données d\'inscription',
            'details': str(e)
        }), 500

#get login history
@user_routes.route('/user/log_history/<period>', methods=['GET'])
@token_required
def getloghistory(period):
    try:
        # Utiliser date directement au lieu de datetime.now().date()
        aujourd_hui = date.today()  # Plus sûr
        date_30_jours = aujourd_hui - timedelta(days= int(period))
        
        req = db.session.query(
            LogConnexion.date_connexion.label('date'),
            func.count(LogConnexion.user_id).label('nombre')
        ).where(
            and_(
                LogConnexion.resultat == "Connexion réussie",
                LogConnexion.date_connexion >= date_30_jours
            )
        ).group_by(
            LogConnexion.date_connexion
        ).order_by(
            LogConnexion.date_connexion.asc()
        ).all()
        
        # Conversion en liste de dictionnaires
        log_history = []
        for row in req:
            log_history.append({
                'date': row.date.isoformat() if hasattr(row.date, 'isoformat') else str(row.date),
                'nombre': row.nombre
            })
        
        return jsonify({
            'message': 'success',
            'log_history': log_history,
            'total': len(log_history)
        }), 200
        
    except Exception as e:
        return jsonify({
            'message': 'error',
            'error': 'Erreur lors de la récupération des données de connexion',
            'details': str(e)
        }), 500



#Get all user activity
@user_routes.route('/user/do_something', methods=['POST'])
@token_required
def do_something():
    data = request.json
    id = data.get('id')
    action = data.get('action')
    statut = data.get('statut')
    date_ac = datetime.now()
    new_activity = UserActivite(action=action,date_action=date_ac,statut=statut,user_id= id)
    db.session.add(new_activity)
    db.session.commit()
    return jsonify({"message": "success"}), 200


#Suspend  user
@user_routes.route('/user/suspend_user', methods=['POST'])
@token_required
def suspend():
    data = request.json
    id =data.get('id')
    suspend = data.get('suspend')
    user = User.query.get(id)
    if not user :
        return jsonify({"message": "User not found"}), 404
    if suspend == True:
        user.isActive = False
    else:
        user.isActive = True
    db.session.commit()
    return jsonify({"message": "success"}), 200
