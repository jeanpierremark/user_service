
from sqlalchemy import Integer, String, Enum, Time, Boolean, ForeignKey, Date, DateTime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship


db = SQLAlchemy()

#Define Enum
define_role = ("Admin","Chercheur","Etudiant","Visiteur")
define_genre = ("M","F")

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(Integer, primary_key=True)
    prenom = db.Column(String(100))
    nom = db.Column(String(100))
    email = db.Column(String(120), unique=True)
    password = db.Column(String(200))
    role = db.Column(Enum(*define_role, name="role"))
    genre = db.Column(Enum(*define_genre, name="genre"))
    age = db.Column(Integer)
    deletable = db.Column(Boolean)



class LogConnexion(db.Model):
    __tablename__='log_connexions'
    id = db.Column(Integer,primary_key = True)
    date_connexion = db.Column(DateTime)
    adresse_Ip = db.Column(String(50))
    resultat = db.Column(String(50))
    user_id = db.Column(Integer, ForeignKey('users.id'))

class UserActivite(db.Model):
    __tablename__='user_activite'
    id = db.Column(Integer, primary_key = True)
    action = db.Column(String(100))
    date_action = db.Column(DateTime)
    user_id = db.Column(Integer, ForeignKey('users.id'))

