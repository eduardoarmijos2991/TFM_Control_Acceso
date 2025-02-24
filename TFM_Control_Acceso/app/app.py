from flask import Flask, request, jsonify, render_template, session, redirect, url_for  # Importamos las librerías necesarias
from flask_sqlalchemy import SQLAlchemy  # Para manejar la base de datos
from flask_migrate import Migrate  # Para gestionar las migraciones de la base de datos
from flask_admin import Admin, AdminIndexView, expose  # Para crear el panel de administración
from flask_admin.contrib.sqla import ModelView  # Para crear vistas basadas en SQLAlchemy en el panel de administración
import logging  # Para registrar mensajes de depuración
import base64
import hashlib

# Importamos los formularios y vistas personalizados
from forms import RegisterUserForm, ChangePasswordForm, ChangeFingerprintForm, DeleteUserForm
from views import RegisterUserView, ChangePasswordView, ChangeFingerprintView, DeleteUserView
from models import db, NewUser, Admin as AdminModel

# Tratamos de importar la librería RPi.GPIO para manejar los pines GPIO de la Raspberry Pi
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(2, GPIO.OUT)
except (RuntimeError, ModuleNotFoundError):
    GPIO_AVAILABLE = False
    print("GPIO no disponible. Asegúrate de estar ejecutando este código en una Raspberry Pi.")

# Importamos las librerías para manejar la autenticación FIDO2
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, AttestationObject
from fido2.server import Fido2Server
from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.ctap import CtapError

# Configuración de la aplicación Flask
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Configuramos la base de datos SQLite
app.secret_key = 'supersecretkey'  # Clave secreta para las sesiones de Flask
db.init_app(app)
migrate = Migrate(app, db)

# Clase personalizada para la vista de índice del panel de administración
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not session.get('admin_logged_in'):
            return redirect(url_for('login'))
        return self.render('admin/index.html')

# Configuración del panel de administración
admin_panel = Admin(app, index_view=MyAdminIndexView(), template_mode='bootstrap3', name='Administración')
admin_panel.add_view(ModelView(NewUser, db.session, name='Usuarios', endpoint='user_admin'))
admin_panel.add_view(RegisterUserView(name='Registrar Usuario', endpoint='register_user'))
admin_panel.add_view(ChangePasswordView(name='Cambiar Contraseña', endpoint='change_password'))
admin_panel.add_view(ChangeFingerprintView(name='Cambiar Huella', endpoint='change_fingerprint'))
admin_panel.add_view(DeleteUserView(name='Borrar Usuario', endpoint='delete_user'))
admin_panel.add_view(ModelView(AdminModel, db.session, name='Administradores', endpoint='admin_admin'))

logging.basicConfig(level=logging.DEBUG)  # Configuramos el nivel de depuración

# Configuración del servidor FIDO2
rp = PublicKeyCredentialRpEntity(id='example.com', name='Example Server')
server = Fido2Server(rp)

# Ruta para iniciar sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = AdminModel.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_logged_in'] = True
            return redirect(url_for('register_user.index'))
        return render_template('login.html', error="Usuario o contraseña incorrectos")
    return render_template('login.html')

# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

# Ruta para la página de registro
@app.route('/register_page')
def register_page():
    return render_template('register.html') if 'admin_logged_in' in session else redirect(url_for('login'))

# Ruta para la página de administración
@app.route('/admin_page')
def admin_page():
    return render_template('admin.html') if 'admin_logged_in' in session else redirect(url_for('login'))

# Ruta para completar el registro de usuario
@app.route('/register/complete', methods=['POST'])
def register_complete():
    data = request.get_json()
    try:
        new_user = NewUser(username=data['username'], fingerprint=data.get('fingerprint', str(data['userId'])))
        new_user.set_password(data.get('password', str(data['userId'])))
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Ruta para iniciar el proceso de registro
@app.route('/register/begin', methods=['POST'])
def register_begin():
    data = request.get_json()
    user = db.session.get(NewUser, data['userId'])
    if not user:
        return jsonify({"error": "User not found"}), 404
    publicKey = PublicKeyCredentialUserEntity(id=str(user.id).encode('utf-8'), name=user.username, display_name=user.username)
    options, state = server.register_begin(publicKey)
    session['state'] = state
    return jsonify({
        "rp": {"name": rp.name, "id": rp.id},
        "user": {"id": base64.b64encode(publicKey.id).decode('utf-8'), "name": publicKey.name, "displayName": publicKey.display_name},
        "publicKeyCredentialParameters": [{"alg": -7, "type": "public-key"}, {"alg": -257, "type": "public-key"}],
        "authenticatorSelection": {"userVerification": "required"}
    })

# Ruta para registrar la huella
@app.route('/register/fingerprint', methods=['POST'])
def register_fingerprint():
    data = request.get_json()
    try:
        client_data = base64.b64decode(data['clientData'])
        attestation_object = base64.b64decode(data['attestationObject'])
        auth_data = server.register_complete(session['state'], client_data, AttestationObject(attestation_object))
        hashed_fingerprint = hashlib.sha256(auth_data.credential_data.credential_id).hexdigest()
        user = db.session.get(NewUser, data['userId'])
        if user:
            user.fingerprint = hashed_fingerprint
            db.session.commit()
            return jsonify({"message": "Fingerprint registered successfully"}), 200
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Ruta para probar la autenticación FIDO2
@app.route('/test_fido', methods=['POST'])
def test_fido():
    try:
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            return jsonify({"error": "No FIDO2 devices found"}), 404
        client = Fido2Client(devices[0], rp)
        info = client.info
        has_fingerprint = 'fingerprint' in info.extensions
        return jsonify({"versions": info.versions, "extensions": info.extensions, "has_fingerprint": has_fingerprint}), 200
    except CtapError as e:
        return jsonify({"error": str(e)}), 500

# Ruta para listar los usuarios
@app.route('/users', methods=['GET'])
def list_users():
    users = NewUser.query.all()
    return render_template('admin/list_users.html', users=users)

# Ruta para actualizar un usuario
@app.route('/users/<int:id>', methods=['PUT'])
def update_user(id):
    data = request.get_json()
    user = db.session.get(NewUser, id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user.username = data.get('username', user.username)
    user.fingerprint = data.get('fingerprint', user.fingerprint)
    db.session.commit()
    return jsonify({"message": "User updated successfully"})

# Ruta para eliminar un usuario
@app.route('/users/<int:id>', methods=['DELETE'])
def delete_user(id):
    user = db.session.get(NewUser, id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"})

# Ruta principal que renderiza la página de acceso
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        return redirect(url_for('access'))
    return render_template('index.html')

# Ruta para manejar el acceso de los usuarios
@app.route('/access', methods=['POST'])
def access():
    username = request.form['username']
    password = request.form.get('password', '')
    action = request.form.get('action')

    # Verificar si es el administrador
    if action == "admin":
        admin = AdminModel.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_logged_in'] = True
            return redirect(url_for('register_user.index'))
        else:
            return render_template('index.html', error="Usuario o contraseña incorrectos para Administrador")

    # Verificar si es un usuario registrado
    user = NewUser.query.filter_by(username=username).first()
    if user and user.check_password(password):
        if GPIO_AVAILABLE:
            GPIO.output(2, GPIO.HIGH)  # Encender el LED
        return f"Acceso concedido a {user.username}", 200

    return render_template('index.html', error="Usuario no registrado o contraseña incorrecta")

# Ruta para cambiar la contraseña de un usuario sin conocer la contraseña anterior (solo para administradores)
@app.route('/change_password/<int:id>', methods=['GET', 'POST'])
def change_password(id):
    user = NewUser.query.get(id)
    if request.method == 'POST':
        new_password = request.form['new_password']
        user.set_password(new_password)
        db.session.commit()
        return f"Contraseña cambiada para el usuario {user.username}"
    return render_template('admin/change_password.html', user=user)

# Ruta para cambiar la huella de un usuario
@app.route('/change_fingerprint/<int:id>', methods=['GET', 'POST'])
def change_fingerprint(id):
    user = NewUser.query.get(id)
    if request.method == 'POST':
        return redirect(url_for('register_fingerprint'))
    return render_template('admin/change_fingerprint.html', user=user)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
