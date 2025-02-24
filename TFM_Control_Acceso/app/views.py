from flask_admin import BaseView, expose  # Importamos las clases BaseView y expose de Flask-Admin para crear vistas personalizadas
from flask_admin.contrib.sqla import ModelView  # Importamos ModelView para crear vistas basadas en SQLAlchemy en el panel de administración
from flask import request, redirect, url_for, flash  # Importamos las funciones necesarias para manejar las solicitudes y redirecciones en Flask
from models import db, NewUser  # Importamos la instancia de la base de datos y el modelo NewUser
from forms import RegisterUserForm, ChangePasswordForm, ChangeFingerprintForm, DeleteUserForm  # Importamos los formularios personalizados

# Definimos una vista personalizada para registrar usuarios
class RegisterUserView(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        form = RegisterUserForm()
        if form.validate_on_submit():
            existing_user = NewUser.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash('Username already exists', 'error')
                return redirect(url_for('.index'))
            new_user = NewUser(username=form.username.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully', 'success')
            return redirect(url_for('.index'))
        return self.render('admin/register_user.html', form=form)

# Definimos una vista personalizada para cambiar la contraseña de un usuario
class ChangePasswordView(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        form = ChangePasswordForm()
        if form.validate_on_submit():
            user = NewUser.query.get(form.id.data)
            if user:
                user.set_password(form.new_password.data)
                db.session.commit()
                flash('Password changed successfully', 'success')
            else:
                flash('User not found', 'error')
            return redirect(url_for('.index'))
        return self.render('admin/change_password.html', form=form)

# Definimos una vista personalizada para cambiar la huella digital de un usuario
class ChangeFingerprintView(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        form = ChangeFingerprintForm()
        if form.validate_on_submit():
            user = NewUser.query.get(form.id.data)
            if user:
                return redirect(url_for('register_fingerprint'))
            else:
                flash('User not found', 'error')
            return redirect(url_for('.index'))
        return self.render('admin/change_fingerprint.html', form=form)

# Definimos una vista personalizada para eliminar un usuario
class DeleteUserView(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        form = DeleteUserForm()
        if form.validate_on_submit():
            user = NewUser.query.filter_by(username=form.username.data).first()
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully', 'success')
            else:
                flash('User not found', 'error')
            return redirect(url_for('.index'))
        return self.render('admin/delete_user.html', form=form)
