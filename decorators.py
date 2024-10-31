# decorators.py
from flask import redirect, url_for, flash
from flask_login import current_user
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Necesitas iniciar sesión para acceder a esta página.', 'danger')
            return redirect(url_for('login.login'))
        if current_user.role != 'admin':
            flash('No tienes permiso para acceder a esta página.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function