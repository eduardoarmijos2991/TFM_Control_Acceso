from flask_sqlalchemy import SQLAlchemy  # Importamos SQLAlchemy para manejar la base de datos
from werkzeug.security import generate_password_hash, check_password_hash  # Importamos funciones para manejar contraseñas

# Inicializamos la instancia de la base de datos
db = SQLAlchemy()

# Definimos el modelo para los usuarios registrados
class NewUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Identificador único para cada usuario
    username = db.Column(db.String(150), unique=True, nullable=False)  # Nombre de usuario único y no nulo
    password_hash = db.Column(db.String(128), nullable=False)  # Hash de la contraseña del usuario
    fingerprint = db.Column(db.String(128), default='pendiente')  # Hash de la huella digital del usuario

    def set_password(self, password):
        # Método para establecer la contraseña del usuario (genera un hash)
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        # Método para verificar la contraseña del usuario (compara el hash almacenado con el hash de la contraseña proporcionada)
        return check_password_hash(self.password_hash, password)

# Definimos el modelo para los administradores
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Identificador único para cada administrador
    username = db.Column(db.String(150), unique=True, nullable=False)  # Nombre de usuario único y no nulo
    password_hash = db.Column(db.String(128), nullable=False)  # Hash de la contraseña del administrador

    def set_password(self, password):
        # Método para establecer la contraseña del administrador (genera un hash)
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        # Método para verificar la contraseña del administrador (compara el hash almacenado con el hash de la contraseña proporcionada)
        return check_password_hash(self.password_hash, password)
