from flask_wtf import FlaskForm  # Importamos FlaskForm para manejar los formularios
from wtforms import StringField, PasswordField, SubmitField  # Importamos los campos necesarios para los formularios
from wtforms.validators import DataRequired  # Importamos un validador para asegurar que los campos no estén vacíos

# Definimos el formulario para registrar usuarios
class RegisterUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])  # Campo para el nombre de usuario
    password = PasswordField('Password', validators=[DataRequired()])  # Campo para la contraseña
    submit = SubmitField('Register')  # Botón para enviar el formulario

# Definimos el formulario para cambiar la contraseña de un usuario
class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])  # Campo para la nueva contraseña
    submit = SubmitField('Change Password')  # Botón para enviar el formulario

# Definimos el formulario para cambiar la huella digital de un usuario
class ChangeFingerprintForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])  # Campo para el nombre de usuario
    submit = SubmitField('Change Fingerprint')  # Botón para enviar el formulario

# Definimos el formulario para eliminar un usuario
class DeleteUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])  # Campo para el nombre de usuario
    submit = SubmitField('Delete User')  # Botón para enviar el formulario
