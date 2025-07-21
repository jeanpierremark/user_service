from flask import Flask,Blueprint
from flask_cors import CORS
from sqlalchemy import inspect 
from models.models import db
from config import Config
from routes.user import user_routes



app = Flask(__name__)

@app.route("/")
def home():
    return "Bienvenue sur votre application Flask !"

CORS(app, origins=["http://localhost:4200"], methods=["GET", "POST", "PUT", "DELETE"], supports_credentials=True)



# Configurations and initializations
app.config.from_object(Config)
db.init_app(app)


#Register routes 
app.register_blueprint(user_routes,url_prefix='/api')


# Function to create tables
def create_tables_if_not_exist():
    inspector = inspect(db.engine)
    existing_tables = inspector.get_table_names()
    tables_to_create = [table for table in db.metadata.tables.keys() if table not in existing_tables]
    if tables_to_create:
        print("Creating tables")
        db.create_all()
    else:
        print("Tables are already created")

# Create tables
with app.app_context():
    create_tables_if_not_exist()

if __name__ == '__main__':
    app.run(debug=True)
