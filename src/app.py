from flask import Flask, render_template, request, redirect, url_for, flash
from flask import jsonify
import re
from datetime import datetime, timedelta
import pyotp
import datetime
import qrcode
from io import BytesIO
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import sha256
import random
from flask_wtf import FlaskForm 
from flask_wtf import RecaptchaField
import requests
import string
from flask import session
from flask_login import logout_user
from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user
from flask_mysqldb import MySQL
from flask_login import UserMixin
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui'  # Clave secreta para CSRF y sesiones
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'cookylanda'
csrf = CSRFProtect(app)
csrf.init_app(app)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

app.config["RECAPTCHA_PUBLIC_KEY"] = "6LflK_0qAAAAANxdoeeznqe1Y9eNayGLoNmlnuHK"  # Clave pública
app.config["RECAPTCHA_PRIVATE_KEY"] = "6LflK_0qAAAAAHsp7yEnUhb1S907mA5HtvuFCcGO"  # Clave privada

mysql = MySQL(app)
csrf = CSRFProtect(app)  # Habilita la protección CSRF
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Ruta a la que redirigir si el usuario no está autenticado

class Usuario:
    def __init__(
        self, 
        idUsuario, 
        nombreCompleto, 
        apePaterno, 
        apeMaterno, 
        usuario, 
        contrasenia, 
        correo, 
        rol, 
        estatus, 
        codigoUsuario, 
        intentos_fallidos=None, 
        bloqueado_hasta=None, 
        ultimo_cambio_contrasenia=None, 
        ultimo_inicio_sesion=None
    ):
        self.idUsuario = idUsuario
        self.nombreCompleto = nombreCompleto
        self.apePaterno = apePaterno
        self.apeMaterno = apeMaterno
        self.usuario = usuario
        self.contrasenia = contrasenia
        self.correo = correo
        self.rol = rol
        self.estatus = estatus
        self.codigoUsuario = codigoUsuario
        self.intentos_fallidos = intentos_fallidos
        self.bloqueado_hasta = bloqueado_hasta
        self.ultimo_cambio_contrasenia = ultimo_cambio_contrasenia
        self.ultimo_inicio_sesion = ultimo_inicio_sesion

class User(UserMixin):
    def __init__(self, id, usuario, contrasenia, rol, activo=True):  # activo tiene un valor predeterminado
        self.id = id
        self.usuario = usuario
        self.contrasenia = contrasenia
        self.rol = rol
        self._activo = activo  # Atributo privado para almacenar el estado

    @staticmethod
    def get_by_username(db, username):
        cursor = db.connection.cursor()
        cursor.execute("SELECT * FROM usuario WHERE usuario = %s", (username,))
        user_data = cursor.fetchone()
        cursor.close()

        if user_data:
            return User(
                id=user_data[0],  # idUsuario
                usuario=user_data[4],  # usuario
                contrasenia=user_data[5],  # contrasenia
                rol=user_data[7],  # rol
                activo=user_data[8] if len(user_data) > 8 else True  # Campo 'activo' si existe
            )
        return None

class WidgetForm(FlaskForm):
    recaptcha = RecaptchaField()

def validate_recaptcha(response):
    secret_key = app.config["RECAPTCHA_PRIVATE_KEY"]  # Accede a la clave privada desde app.config
    payload = {
        'secret': secret_key,
        'response': response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()
    return result.get('success', False)

def generar_codigo_usuario(rol):
    # Prefijo según el rol
    if rol == 'Administrador':
        prefijo = 'ADM'
    elif rol == 'Cocinero':
        prefijo = 'COC'
    elif rol == 'Vendedor':
        prefijo = 'VEN'
    elif rol == 'Cliente':
        prefijo = 'CLI'
    else:
        prefijo = 'USR'  # Prefijo por defecto

    # Generar un número aleatorio de 4 dígitos
    numero = ''.join(random.choices(string.digits, k=4))

    # Combinar prefijo y número
    return f"{prefijo}-{numero}"

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.rol not in roles:
                flash("No tienes permisos para acceder a esta página.", "error")
                return redirect(url_for('acceso_denegado'))  # Redirige a 'acceso_denegado'
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/acceso_denegado')
def acceso_denegado():
    return render_template('acceso_denegado.html')

def validar_contraseña(contraseña):
    # Verifica que la contraseña tenga al menos 8 caracteres
    if len(contraseña) < 8:
        return "La contraseña debe tener al menos 8 caracteres."
    # Verifica que la contraseña tenga al menos una mayúscula
    if not re.search(r"[A-Z]", contraseña):
        return "La contraseña debe contener al menos una letra mayúscula."
    # Verifica que la contraseña tenga al menos una minúscula
    if not re.search(r"[a-z]", contraseña):
        return "La contraseña debe contener al menos una letra minúscula."
    # Verifica que la contraseña tenga al menos un número
    if not re.search(r"[0-9]", contraseña):
        return "La contraseña debe contener al menos un número."
    # Verifica que la contraseña tenga al menos un carácter especial
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", contraseña):
        return "La contraseña debe contener al menos un carácter especial."
    return None  # Si la contraseña es válida, devuelve None

@app.before_request
def clear_session():
    global session_cleared
    if not session_cleared:
        session.clear()
        logout_user()
        session_cleared = True

@login_manager.user_loader
def load_user(id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM usuario WHERE idUsuario = %s", (id,))
    user_data = cursor.fetchone()
    cursor.close()

    if user_data:
        return User(
            id=user_data[0],  # idUsuario
            usuario=user_data[4],  # usuario
            contrasenia=user_data[5],  # contrasenia
            rol=user_data[7],  # rol
            activo=user_data[8] if len(user_data) > 8 else True  # Campo 'activo' si existe
        )
    return None

@app.route('/')
def index():
    return render_template('index.html')  # Renderiza la página principal directamente
session_cleared = False

# Remove or modify this function
@app.before_request
def before_request():
    if current_user.is_authenticated:
        # Renovar la sesión
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=10)
        session.modified = True

# Definir rutas después de que 'app' esté definido
from datetime import datetime, timedelta

@app.route('/dashboard')
@login_required
def dashboard():
    # Verificar si la sesión ha expirado
    if datetime.now() > current_user.get_id().expires_at:  # Suponiendo que tienes un campo expires_at en tu modelo de usuario
        logout_user()
        flash("Tu sesión ha expirado. Por favor, inicia sesión nuevamente.", "warning")
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Obtener la respuesta del CAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')

        # Validar el CAPTCHA
        if not validate_recaptcha(recaptcha_response):
            flash("Por favor, completa el CAPTCHA.", "error")
            return redirect(url_for('login'))

        # Obtener datos del formulario
        usuario = request.form.get('usuario')
        contrasenia = request.form.get('contrasenia')

        if not usuario or not contrasenia:
            flash("Por favor, rellena todos los campos.", "error")
            return redirect(url_for('login'))

        # Verificar si el usuario está bloqueado
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT bloqueado_hasta FROM usuario WHERE usuario = %s", (usuario,))
        bloqueado_hasta = cursor.fetchone()

        if bloqueado_hasta and bloqueado_hasta[0] and datetime.now() < bloqueado_hasta[0]:
            flash("Tu cuenta está bloqueada temporalmente. Inténtalo más tarde.", "error")
            return redirect(url_for('login'))

        # Verificar el usuario y la contraseña
        cursor.execute("SELECT * FROM usuario WHERE usuario = %s", (usuario,))
        user_data = cursor.fetchone()

        if user_data:
            if check_password_hash(user_data[5], contrasenia):  # Índice 5 es la contraseña
                # Reiniciar intentos fallidos
                cursor.execute("UPDATE usuario SET intentos_fallidos = 0 WHERE usuario = %s", (usuario,))
                
                # Registrar el último inicio de sesión
                cursor.execute("UPDATE usuario SET ultimo_inicio_sesion = %s WHERE usuario = %s", (datetime.now(), usuario))
                mysql.connection.commit()

                # Verificar si necesita cambiar la contraseña
                cursor.execute("SELECT ultimo_cambio_contrasenia FROM usuario WHERE usuario = %s", (usuario,))
                ultimo_cambio = cursor.fetchone()[0]

                if datetime.now() - ultimo_cambio > timedelta(days=90):  # Cambiar cada 90 días
                    flash("Debes cambiar tu contraseña. Ha pasado más de 90 días desde el último cambio.", "warning")
                    return redirect(url_for('cambiar_contrasenia'))  # Redirigir a la página de cambio de contraseña

                # Iniciar sesión
                user = User(user_data[0], user_data[4], user_data[5], user_data[7])
                login_user(user)

                # Redirigir según el rol
                if user.rol == 'Cliente':
                    return redirect(url_for('ventas'))
                elif user.rol == 'Administrador':
                    return redirect(url_for('admin'))
                elif user.rol == 'Cocinero':
                    return redirect(url_for('recetas'))
                elif user.rol == 'Vendedor':
                    return redirect(url_for('vendedor'))
                else:
                    return redirect(url_for('index'))
            else:
                # Incrementar intentos fallidos
                cursor.execute("UPDATE usuario SET intentos_fallidos = intentos_fallidos + 1 WHERE usuario = %s", (usuario,))
                mysql.connection.commit()

                # Verificar si superó los 3 intentos
                cursor.execute("SELECT intentos_fallidos FROM usuario WHERE usuario = %s", (usuario,))
                intentos_fallidos = cursor.fetchone()[0]

                if intentos_fallidos >= 3:
                    # Bloquear al usuario por 5 minutos
                    bloqueado_hasta = datetime.now() + timedelta(minutes=5)
                    cursor.execute("UPDATE usuario SET bloqueado_hasta = %s WHERE usuario = %s", (bloqueado_hasta, usuario))
                    mysql.connection.commit()
                    flash("Has excedido el número de intentos. Tu cuenta está bloqueada por 5 minutos.", "error")
                else:
                    flash(f"Contraseña incorrecta. Te quedan {3 - intentos_fallidos} intentos.", "error")
                return redirect(url_for('login'))
        else:
            flash("Usuario no encontrado.", "error")
            return redirect(url_for('login'))

    return render_template('auth/login.html', recaptcha_public_key=app.config['RECAPTCHA_PUBLIC_KEY'])

from flask_login import logout_user

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Cierra la sesión del usuario
    flash("Has cerrado sesión correctamente.", "success")
    return redirect(url_for('login'))  # Redirige al login

@app.route('/vendedor')
@login_required
@roles_required('Vendedor')  # Solo usuarios con rol 'Vendedor' pueden acceder
def vendedor(): 
    return render_template('vendedor.html')  # Renderiza el template vendedor.html

@app.route('/recetas')
@login_required
@roles_required('Cocinero', 'Administrador')
def recetas():
    return render_template('recetas.html')

@app.route('/cambiar_contrasenia', methods=['GET', 'POST'])
@login_required
def cambiar_contrasenia():
    if request.method == 'POST':
        contrasenia_actual = request.form.get('contrasenia_actual')
        nueva_contrasenia = request.form.get('nueva_contrasenia')
        confirmar_contrasenia = request.form.get('confirmar_contrasenia')

        # Verificar la contraseña actual
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT contrasenia FROM usuario WHERE idUsuario = %s", (current_user.id,))
        contrasenia_hash = cursor.fetchone()[0]

        if not check_password_hash(contrasenia_hash, contrasenia_actual):
            flash("La contraseña actual es incorrecta.", "error")
            return redirect(url_for('cambiar_contrasenia'))

        # Validar la nueva contraseña
        if nueva_contrasenia != confirmar_contrasenia:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for('cambiar_contrasenia'))

        mensaje_error = validar_contraseña(nueva_contrasenia)
        if mensaje_error:
            flash(mensaje_error, "error")
            return redirect(url_for('cambiar_contrasenia'))

        # Actualizar la contraseña
        nueva_contrasenia_hash = generate_password_hash(nueva_contrasenia)
        cursor.execute(
            "UPDATE usuario SET contrasenia = %s, ultimo_cambio_contrasenia = %s WHERE idUsuario = %s",
            (nueva_contrasenia_hash, datetime.now(), current_user.id)
        )
        mysql.connection.commit()
        flash("Contraseña cambiada exitosamente.", "success")
        return redirect(url_for('ventas'))  # Redirigir al dashboard

    return render_template('auth/cambiar_contrasenia.html')


@app.route('/ventas')
@login_required
@roles_required('Cliente', 'Vendedor')
def ventas():
    return render_template('ventas.html')

@app.route('/catalogo')
@login_required
@roles_required('Cliente')
def catalogo():
    return render_template('catalogo.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador')  # Solo el rol 'Administrador' puede acceder
def admin():
    if request.method == 'POST':
        nombreCompleto = request.form['nombreCompleto']
        apePaterno = request.form['apePaterno']
        apeMaterno = request.form['apeMaterno']
        usuario = request.form['usuario']
        contrasenia = generate_password_hash(request.form['contrasenia'])
        correo = request.form['correo']
        rol = request.form['rol']

        # Generar el código de usuario
        codigoUsuario = generar_codigo_usuario(rol)

        cursor = mysql.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO usuario (nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, codigoUsuario) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, codigoUsuario)
            )
            mysql.connection.commit()
            flash("Usuario creado exitosamente.", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Error al crear el usuario: {str(e)}", "error")
        finally:
            cursor.close()
        return redirect(url_for('admin'))  # Redirige de vuelta a la página de administración

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM usuario")
    usuarios_tuplas = cursor.fetchall()
    usuarios = [Usuario(*usuario) for usuario in usuarios_tuplas]
    cursor.close()
    return render_template('admin.html', usuarios=usuarios)
@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador')
def editar_usuario(id):
    if current_user.rol != 'Administrador':
        flash("No tienes permisos para realizar esta acción.", "error")
        return redirect(url_for('ventas'))
    
    cursor = mysql.connection.cursor()
    if request.method == 'POST':
        nombreCompleto = request.form['nombreCompleto']
        apePaterno = request.form['apePaterno']
        apeMaterno = request.form['apeMaterno']
        usuario = request.form['usuario']
        correo = request.form['correo']

        try:
            cursor.execute(
                "UPDATE usuario SET nombreCompleto = %s, apePaterno = %s, apeMaterno = %s, usuario = %s, correo = %s WHERE idUsuario = %s",
                (nombreCompleto, apePaterno, apeMaterno, usuario, correo, id)
            )
            mysql.connection.commit()
            flash("Usuario actualizado exitosamente.", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Error al actualizar el usuario: {str(e)}", "error")
        finally:
            cursor.close()
        return redirect(url_for('administrador'))
    
    cursor.execute("SELECT * FROM usuario WHERE idUsuario = %s", (id,))
    usuario = cursor.fetchone()
    cursor.close()
    return render_template('editar_usuario.html', usuario=usuario)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        # Verificar si el usuario ya completó el formulario y está en la fase de validación del token
        if 'secret' in session and 'token' in request.form:
            # Validar el token proporcionado por el usuario
            secret = session['secret']
            token = request.form['token']

            # Verificar el token
            totp = pyotp.TOTP(secret)
            if totp.verify(token):
                # Token válido, completar el registro
                nombreCompleto = session['nombreCompleto']
                apePaterno = session['apePaterno']
                apeMaterno = session['apeMaterno']
                usuario = session['usuario']
                contrasenia = session['contrasenia']
                correo = session['correo']
                rol = session['rol']

                # Insertar el nuevo usuario en la base de datos
                cursor = mysql.connection.cursor()
                try:
                    cursor.execute(
                        "INSERT INTO usuario (nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, codigoUsuario) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, generar_codigo_usuario(rol))
                    )
                    mysql.connection.commit()
                    flash("Usuario registrado exitosamente.", "success")
                    # Limpiar la sesión
                    session.pop('nombreCompleto', None)
                    session.pop('apePaterno', None)
                    session.pop('apeMaterno', None)
                    session.pop('usuario', None)
                    session.pop('contrasenia', None)
                    session.pop('correo', None)
                    session.pop('rol', None)
                    session.pop('secret', None)
                    return redirect(url_for('login'))
                except Exception as e:
                    mysql.connection.rollback()
                    flash(f"Error al registrar el usuario: {str(e)}", "error")
                    return redirect(url_for('registro'))
                finally:
                    cursor.close()
            else:
                flash("Token inválido. Inténtalo de nuevo.", "error")
                return redirect(url_for('registro'))

        # Si no es la fase de validación del token, procesar el formulario inicial
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not validate_recaptcha(recaptcha_response):
            flash('Por favor, completa el CAPTCHA.', 'error')
            return redirect(url_for('registro'))

        # Obtener datos del formulario
        nombreCompleto = request.form.get('nombreCompleto')
        apePaterno = request.form.get('apePaterno')
        apeMaterno = request.form.get('apeMaterno')
        usuario = request.form.get('usuario')
        contrasenia = request.form.get('contrasenia')
        correo = request.form.get('correo')
        rol = 'Cliente'  # Rol por defecto

        # Validar los datos del formulario
        if not re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{2,}$", nombreCompleto):
            flash("El nombre completo debe contener solo letras y espacios, y tener al menos 2 caracteres.", "error")
            return redirect(url_for('registro'))

        if not re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{2,}$", apePaterno):
            flash("El apellido paterno debe contener solo letras y espacios, y tener al menos 2 caracteres.", "error")
            return redirect(url_for('registro'))

        if not re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{2,}$", apeMaterno):
            flash("El apellido materno debe contener solo letras y espacios, y tener al menos 2 caracteres.", "error")
            return redirect(url_for('registro'))

        if not re.match(r"^[a-zA-Z0-9_]{5,20}$", usuario):
            flash("El usuario debe tener entre 5 y 20 caracteres y solo puede contener letras, números y guiones bajos.", "error")
            return redirect(url_for('registro'))

        # Verificar si el usuario ya existe
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM usuario WHERE usuario = %s", (usuario,))
        if cursor.fetchone():
            flash("El nombre de usuario ya está en uso.", "error")
            cursor.close()
            return redirect(url_for('registro'))

        # Validar la contraseña
        mensaje_error = validar_contraseña(contrasenia)
        if mensaje_error:
            flash(mensaje_error, "error")
            return redirect(url_for('registro'))

        # Hash de la contraseña
        contrasenia_hash = generate_password_hash(contrasenia)

        # Guardar los datos en la sesión para usarlos después de la validación del token
        session['nombreCompleto'] = nombreCompleto
        session['apePaterno'] = apePaterno
        session['apeMaterno'] = apeMaterno
        session['usuario'] = usuario
        session['contrasenia'] = contrasenia_hash
        session['correo'] = correo
        session['rol'] = rol

        # Generar un secreto para el usuario
        secret = pyotp.random_base32()
        session['secret'] = secret

        # Generar la URL para el código QR
        provisioning_url = pyotp.totp.TOTP(secret).provisioning_uri(name=usuario, issuer_name="TuAplicación")

        # Generar el código QR
        img = qrcode.make(provisioning_url)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        # Mostrar la página de validación del token
        return render_template('auth/validar_token.html', qr_code=img_str)

    # Si el método es GET, mostrar el formulario de registro
    return render_template('auth/registro.html', recaptcha_public_key=app.config['RECAPTCHA_PUBLIC_KEY'])

@app.route('/administrador')
@login_required
@roles_required('Administrador') 
def administrador():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM usuario")
    usuarios_tuplas = cursor.fetchall()  # Obtén las tuplas
    cursor.close()

    # Convierte las tuplas en objetos Usuario
    usuarios = [Usuario(*usuario) for usuario in usuarios_tuplas]
    return render_template('administrador.html', usuarios=usuarios)

# Ruta para eliminar usuarios (solo administrador)
@app.route('/eliminar_usuario/<int:id>', methods=['POST'])
@login_required
def eliminar_usuario(id):
    if current_user.rol != 'Administrador':
        flash("No tienes permisos para realizar esta acción.", "error")
        return redirect(url_for('ventas'))
    
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("DELETE FROM usuario WHERE idUsuario = %s", (id,))
        mysql.connection.commit()
        flash("Usuario eliminado exitosamente.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error al eliminar el usuario: {str(e)}", "error")
    finally:
        cursor.close()
    return redirect(url_for('administrador'))

if __name__ == '__main__':
    app.run(debug=True)