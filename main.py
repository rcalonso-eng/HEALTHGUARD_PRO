# main.py
from models import (db, Usuario, RolDetalle, UsuarioRol, SignoVital, 
                    Alerta, HistorialClinico, Permiso, RolPermiso,
                    UmbralAlerta, Dispositivo, Notificacion,
                    Auditoria, RespaldoLogico, RespaldoFisico)
from models import db, Usuario, RolDetalle, UsuarioRol, SignoVital, Alerta, HistorialClinico
from flask import Flask, flash, render_template, request, redirect, session, url_for
from models import db, Usuario, RolDetalle, UsuarioRol, SignoVital, Alerta, HistorialClinico
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import timedelta
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash
print(generate_password_hash("admin123", method='pbkdf2:sha256'))
import datetime



# ---------- Helpers de conversión segura ----------
def to_float(valor):
    """Convierte un string a float. Devuelve None si está vacío o es inválido."""
    if valor is None:
        return None
    valor = str(valor).strip()
    if valor == '':
        return None
    try:
        return float(valor)
    except (ValueError, TypeError):
        return None


def to_int(valor):
    """Convierte un string a int. Devuelve None si está vacío o es inválido."""
    if valor is None:
        return None
    valor = str(valor).strip()
    if valor == '':
        return None
    try:
        return int(valor)
    except (ValueError, TypeError):
        return None
    
def validar_signos_vitales(datos):
    """
    Valida los rangos de los signos vitales.
    Retorna (es_valido, mensaje_error).
    """
    errores = []
    
    # Rangos definidos según los CHECK de tu SQL
    rangos = {
        'glucosa': (50, 400, 'Glucosa'),
        'presion_sistolica': (50, 250, 'Presión Sistólica'),
        'presion_diastolica': (30, 150, 'Presión Diastólica'),
        'peso': (20, 300, 'Peso'),
        'frecuencia_cardiaca': (30, 200, 'Frecuencia Cardíaca'),
        'oxigenacion': (50, 100, 'Oxigenación')
    }

    # Validar que al menos uno tenga valor
    valores = [datos.get(k) for k in rangos.keys()]
    if all(v is None for v in valores):
        errores.append("Debes registrar al menos un signo vital.")

    # Validar cada uno si tiene valor
    for campo, (minimo, maximo, nombre) in rangos.items():
        valor = datos.get(campo)
        if valor is not None:
            if not (minimo <= valor <= maximo):
                errores.append(f"{nombre} fuera de rango válido ({minimo}-{maximo}).")
    
    # Validación de coherencia: Sistólica > Diastólica
    sis = datos.get('presion_sistolica')
    dia = datos.get('presion_diastolica')
    if sis is not None and dia is not None:
        if sis <= dia:
            errores.append("La presión sistólica debe ser mayor que la diastólica.")

    if errores:
        return False, " | ".join(errores)
    return True, "OK"  

# ---------- Fin helpers ----------

app = Flask(__name__)
Bootstrap(app)

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1234@127.0.0.1/healthguard_pro'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'clave_secreta_healthguard'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor inicia sesión para acceder.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)

# ---------- Rutas de autenticación ----------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Usamos el método del modelo que ya gestiona los intentos y bloqueos
        usuario = Usuario.validar(email, password)
        
        if usuario:
            # Validación de seguridad adicional (por si acaso)
            if usuario.cuenta_bloqueada:
                flash('Tu cuenta está bloqueada por demasiados intentos fallidos.', 'danger')
                return render_template('auth/login.html')
            if not usuario.estado:
                flash('Tu cuenta está desactivada. Contacta al administrador.', 'danger')
                return render_template('auth/login.html')

            # Iniciar sesión correctamente
            login_user(usuario)
            usuario.ultimo_login = datetime.datetime.utcnow()
            usuario.intentos_login = 0
            db.session.commit()
            
            session['user_name'] = usuario.nombre
            return redirect(url_for('dashboard'))
        else:
            # El modelo ya incrementó los intentos o bloqueó la cuenta si fue necesario
            flash('Credenciales inválidas o cuenta bloqueada.', 'danger')
            return render_template('auth/login.html')
            
    # Si es GET, simplemente muestra el formulario
    return render_template('auth/login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    # Si el usuario ya está autenticado, redirigir al dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        telefono = request.form.get('telefono', '').strip() or None
        direccion = request.form.get('direccion', '').strip() or None
        
        # Validaciones básicas
        if not nombre or not email or not password:
            flash('Nombre, email y contraseña son obligatorios.', 'danger')
            return render_template('auth/registro.html')
        
        if len(password) < 6:
            flash('La contraseña debe tener al menos 6 caracteres.', 'danger')
            return render_template('auth/registro.html')
        
        # Verificar que el email no esté ya registrado
        existente = Usuario.query.filter_by(email=email).first()
        if existente:
            flash('Ya existe una cuenta con ese email.', 'danger')
            return render_template('auth/registro.html')
        
        # Crear el nuevo usuario
        nuevo = Usuario(
            nombre=nombre,
            email=email,
            telefono=telefono,
            direccion=direccion,
            estado=True
        )
        nuevo.password = password   # el setter hashea automáticamente
        nuevo.agregar()
        
        # Asignar el rol 'paciente' por defecto (rol_id = 8 según el SQL)
        rol_paciente = RolDetalle.query.filter_by(nombre_rol='paciente').first()
        if rol_paciente:
            asignacion = UsuarioRol(
                usuario_id=nuevo.usuario_id,
                rol_id=rol_paciente.rol_id,
                asignado_por=nuevo.usuario_id,   # se auto-asigna al registrarse
                es_rol_principal=True
            )
            db.session.add(asignacion)
            db.session.commit()
        
        flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/registro.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------- Dashboard ----------
#@app.route('/dashboard')
#@login_required
#def dashboard():
    # Datos para el panel según el rol
#    if current_user.is_admin():
        #total_pacientes = Usuario.query.join(UsuarioRol).join(RolDetalle).filter(RolDetalle.nombre_rol.like('paciente%')).count()
#        total_pacientes = Usuario.query.join(Usuario.roles).join(RolDetalle).filter(RolDetalle.nombre_rol.like('paciente%')).count()
#        alertas_activas = Alerta.query.filter_by(estado='activa').count()
#        return render_template('dashboard.html', total_pacientes=total_pacientes, alertas_activas=alertas_activas)
#    elif current_user.is_medico() or current_user.is_enfermero():
        # Médico ve sus pacientes (simplificado: todos los pacientes)
        #pacientes = Usuario.query.join(UsuarioRol).join(RolDetalle).filter(RolDetalle.nombre_rol.like('paciente%')).all()
#        pacientes = Usuario.query.join(Usuario.roles).join(RolDetalle).filter(RolDetalle.nombre_rol.like('paciente%')).all()
#        return render_template('dashboard.html', pacientes=pacientes)
#    elif current_user.is_paciente():
        # Paciente ve sus propios datos
#        return redirect(url_for('ver_mis_signos'))
#    else:
#        return redirect(url_for('login'))

# ---------- Gestión de Pacientes (solo admin/medico) ----------
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin():
        # Total de pacientes (rol paciente)
        total_pacientes = db.session.query(Usuario).join(UsuarioRol, Usuario.usuario_id == UsuarioRol.usuario_id)\
                                   .join(RolDetalle, UsuarioRol.rol_id == RolDetalle.rol_id)\
                                   .filter(RolDetalle.nombre_rol.like('paciente%'), Usuario.estado == True).count()
        alertas_activas = Alerta.query.filter_by(estado='activa').count()
        return render_template('dashboard.html', total_pacientes=total_pacientes, alertas_activas=alertas_activas)
    elif current_user.is_medico() or current_user.is_enfermero():
        # Lista de pacientes (todos los pacientes)
        pacientes = db.session.query(Usuario).join(UsuarioRol, Usuario.usuario_id == UsuarioRol.usuario_id)\
                                .join(RolDetalle, UsuarioRol.rol_id == RolDetalle.rol_id)\
                                .filter(RolDetalle.nombre_rol.like('paciente%'), Usuario.estado == True).all()
        return render_template('dashboard.html', pacientes=pacientes)
    elif current_user.is_paciente():
        return redirect(url_for('ver_mis_signos'))
    else:
        return redirect(url_for('login'))

@app.route('/pacientes')
@login_required
def listar_pacientes():
    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    pacientes = db.session.query(Usuario).join(UsuarioRol, Usuario.usuario_id == UsuarioRol.usuario_id)\
                            .join(RolDetalle, UsuarioRol.rol_id == RolDetalle.rol_id)\
                            .filter(RolDetalle.nombre_rol.like('paciente%'), Usuario.estado == True).all()
    return render_template('pacientes/listar.html', pacientes=pacientes)

#@app.route('/pacientes')
#@login_required
#def listar_pacientes():
#    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero()):
#        flash('No autorizado', 'danger')
#        return redirect(url_for('dashboard'))
#    # Obtener usuarios con rol paciente
#    #pacientes = Usuario.query.join(UsuarioRol).join(RolDetalle).filter(RolDetalle.nombre_rol.like('paciente%')).all()
#    pacientes = Usuario.query.join(Usuario.roles).join(RolDetalle).filter(RolDetalle.nombre_rol.like('paciente%')).all()
#    return render_template('pacientes/listar.html', pacientes=pacientes)

@app.route('/pacientes/agregar', methods=['GET', 'POST'])
@login_required
def agregar_paciente():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('listar_pacientes'))
    if request.method == 'POST':
        # Crear usuario paciente
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        telefono = request.form.get('telefono')
        direccion = request.form.get('direccion')
        codigo_postal = request.form.get('codigo_postal')
        genero = request.form.get('genero')  # campo adicional? no está en tabla usuarios, se podría agregar
        nuevo = Usuario(
            nombre=nombre,
            email=email,
            telefono=telefono,
            direccion=direccion,
            codigo_postal=codigo_postal,
            estado=True
        )
        nuevo.password = password
        nuevo.agregar()
        # Asignar rol paciente (por defecto paciente básico, rol_id=8 según script)
        rol_paciente = RolDetalle.query.filter_by(nombre_rol='paciente').first()
        if rol_paciente:
            asignacion = UsuarioRol(
                usuario_id=nuevo.usuario_id,
                rol_id=rol_paciente.rol_id,
                asignado_por=current_user.usuario_id,
                es_rol_principal=True
            )
            db.session.add(asignacion)
            db.session.commit()
        flash('Paciente creado exitosamente', 'success')
        return redirect(url_for('listar_pacientes'))
    return render_template('pacientes/agregar.html')

@app.route('/pacientes/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_paciente(id):
    if not (current_user.is_admin() or current_user.is_medico()):
        flash('No autorizado', 'danger')
        return redirect(url_for('listar_pacientes'))
    paciente = Usuario.query.get_or_404(id)
    if request.method == 'POST':
        paciente.nombre = request.form['nombre']
        paciente.telefono = request.form.get('telefono')
        paciente.direccion = request.form.get('direccion')
        paciente.codigo_postal = request.form.get('codigo_postal')
        if request.form.get('password'):
            paciente.password = request.form['password']
        paciente.editar()
        flash('Paciente actualizado', 'success')
        return redirect(url_for('listar_pacientes'))
    return render_template('pacientes/editar.html', paciente=paciente)

@app.route('/pacientes/eliminar/<int:id>')
@login_required
def eliminar_paciente(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('listar_pacientes'))
    paciente = Usuario.query.get_or_404(id)
    # Eliminación lógica: marcar estado=False
    paciente.estado = False
    paciente.editar()
    flash('Paciente desactivado', 'success')
    return redirect(url_for('listar_pacientes'))

# ---------- Signos Vitales ----------
@app.route('/paciente/<int:paciente_id>/signos')
@login_required
def listar_signos(paciente_id):
    paciente = Usuario.query.get_or_404(paciente_id)
    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero() or current_user.usuario_id == paciente_id):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    signos = SignoVital.consulta_por_paciente(paciente_id)
    return render_template('signos/listar.html', paciente=paciente, signos=signos)

@app.route('/paciente/<int:paciente_id>/signos/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_signo(paciente_id):
    paciente = Usuario.query.get_or_404(paciente_id)
    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # 1. Conversión segura de tipos
        glucosa = to_float(request.form.get('glucosa'))
        sistolica = to_int(request.form.get('sistolica'))
        diastolica = to_int(request.form.get('diastolica'))
        peso = to_float(request.form.get('peso'))
        fc = to_int(request.form.get('fc'))
        oxigenacion = to_float(request.form.get('oxigenacion'))
        
        # 2. Agrupamos los datos para la validación
        datos_signos = {
            'glucosa': glucosa,
            'presion_sistolica': sistolica,
            'presion_diastolica': diastolica,
            'peso': peso,
            'frecuencia_cardiaca': fc,
            'oxigenacion': oxigenacion
        }

        # 3. Validar con la nueva función
        es_valido, mensaje = validar_signos_vitales(datos_signos)
        
        if not es_valido:
            flash(mensaje, 'danger')
            return render_template('signos/agregar.html', paciente=paciente)
        
        # 4. Guardar en Base de Datos
        signo = SignoVital(
            paciente_id=paciente_id,
            **datos_signos,  # Desempaqueta el diccionario automáticamente
            tipo_registro='manual',
            observaciones=request.form.get('observaciones')
        )
        signo.agregar()
        flash('Signo vital registrado exitosamente.', 'success')
        return redirect(url_for('listar_signos', paciente_id=paciente_id))
    
    # Si es GET, mostrar formulario
    return render_template('signos/agregar.html', paciente=paciente)

@app.route('/signos/ver/<int:signo_id>')
@login_required
def ver_signo(signo_id):
    signo = SignoVital.query.get_or_404(signo_id)
    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero() or current_user.usuario_id == signo.paciente_id):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('signos/ver.html', signo=signo)

# ---------- Alertas ----------
@app.route('/alertas')
@login_required
def listar_alertas():
    if current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero():
        alertas = Alerta.consulta_activas()
    elif current_user.is_paciente():
        alertas = Alerta.consulta_por_paciente(current_user.usuario_id)
    else:
        alertas = []
    return render_template('alertas/listar.html', alertas=alertas)

@app.route('/alerta/<int:alerta_id>/resolver', methods=['GET', 'POST'])
@login_required
def resolver_alerta(alerta_id):
    alerta = Alerta.query.get_or_404(alerta_id)
    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero()):
        flash('No autorizado', 'danger')
        return redirect(url_for('listar_alertas'))
    if request.method == 'POST':
        alerta.estado = 'resuelta'
        alerta.fecha_resolucion = datetime.datetime.utcnow()
        alerta.resuelta_por = current_user.usuario_id
        alerta.accion_tomada = request.form.get('accion')
        alerta.editar()
        flash('Alerta resuelta', 'success')
        return redirect(url_for('listar_alertas'))
    return render_template('alertas/resolver.html', alerta=alerta)

# ---------- Historial Clínico ----------
@app.route('/paciente/<int:paciente_id>/historial')
@login_required
def listar_historial(paciente_id):
    paciente = Usuario.query.get_or_404(paciente_id)
    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero() or current_user.usuario_id == paciente_id):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    historial = HistorialClinico.consulta_por_paciente(paciente_id)
    return render_template('historial/listar.html', paciente=paciente, historial=historial)

@app.route('/paciente/<int:paciente_id>/historial/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_historial(paciente_id):
    paciente = Usuario.query.get_or_404(paciente_id)
    if not (current_user.is_admin() or current_user.is_medico()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        entrada = HistorialClinico(
            paciente_id=paciente_id,
            tipo_entrada=request.form['tipo_entrada'],
            titulo=request.form['titulo'],
            descripcion=request.form.get('descripcion'),
            profesional_id=current_user.usuario_id,
            es_urgente=('urgente' in request.form),
            categoria=request.form.get('categoria'),
            nivel_confidencialidad=request.form.get('nivel_confidencialidad', 'medio')
        )
        entrada.agregar()
        flash('Entrada agregada al historial', 'success')
        return redirect(url_for('listar_historial', paciente_id=paciente_id))
    return render_template('historial/agregar.html', paciente=paciente)

# ---------- Rutas para pacientes (ver sus propios datos) ----------
@app.route('/mis-signos')
@login_required
def ver_mis_signos():
    if not current_user.is_paciente():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    return redirect(url_for('listar_signos', paciente_id=current_user.usuario_id))

@app.route('/mis-alertas')
@login_required
def ver_mis_alertas():
    if not current_user.is_paciente():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    return redirect(url_for('listar_alertas'))

@app.route('/mi-historial')
@login_required
def ver_mi_historial():
    if not current_user.is_paciente():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    return redirect(url_for('listar_historial', paciente_id=current_user.usuario_id))

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    if request.method == 'POST':
        nombre = request.form['nombre']
        telefono = request.form.get('telefono')
        direccion = request.form.get('direccion')
        codigo_postal = request.form.get('codigo_postal')
        # Actualizar usuario (se puede llamar al procedimiento almacenado si se desea)
        current_user.nombre = nombre
        current_user.telefono = telefono
        current_user.direccion = direccion
        current_user.codigo_postal = codigo_postal
        db.session.commit()
        flash('Perfil actualizado correctamente', 'success')
        return redirect(url_for('perfil'))
    return render_template('perfil.html', usuario=current_user)

# ---------- Gestión de Usuarios (solo admin) ----------
@app.route('/usuarios')
@login_required
def listar_usuarios():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    usuarios = Usuario.query.order_by(Usuario.nombre).all()
    return render_template('usuarios/listar.html', usuarios=usuarios)


@app.route('/usuarios/agregar', methods=['GET', 'POST'])
@login_required
def agregar_usuario():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    roles = RolDetalle.query.order_by(RolDetalle.nivel_permisos.desc()).all()
    if request.method == 'POST':
        nombre = request.form['nombre'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        telefono = request.form.get('telefono') or None
        direccion = request.form.get('direccion') or None
        genero = request.form.get('genero') or None
        rol_id = request.form.get('rol_id')

        if Usuario.query.filter_by(email=email).first():
            flash('El email ya está registrado.', 'danger')
            return render_template('usuarios/agregar.html', roles=roles)

        nuevo = Usuario(nombre=nombre, email=email, telefono=telefono,
                        direccion=direccion, genero=genero, estado=True)
        nuevo.password = password
        db.session.add(nuevo)
        db.session.flush()  # para obtener el ID antes del commit

        if rol_id:
            asignacion = UsuarioRol(
                usuario_id=nuevo.usuario_id,
                rol_id=int(rol_id),
                asignado_por=current_user.usuario_id,
                es_rol_principal=True
            )
            db.session.add(asignacion)
        db.session.commit()
        flash('Usuario creado exitosamente.', 'success')
        return redirect(url_for('listar_usuarios'))
    return render_template('usuarios/agregar.html', roles=roles)


@app.route('/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    usuario = Usuario.query.get_or_404(id)
    roles = RolDetalle.query.order_by(RolDetalle.nivel_permisos.desc()).all()
    if request.method == 'POST':
        usuario.nombre = request.form['nombre'].strip()
        usuario.telefono = request.form.get('telefono') or None
        usuario.direccion = request.form.get('direccion') or None
        usuario.genero = request.form.get('genero') or None
        usuario.estado = 'estado' in request.form
        if request.form.get('password'):
            usuario.password = request.form['password']

        # Actualizar rol principal si se especifica
        rol_id = request.form.get('rol_id')
        if rol_id:
            # Quitar el rol principal anterior
            UsuarioRol.query.filter_by(usuario_id=id, es_rol_principal=True)\
                            .update({'es_rol_principal': False})
            existente = UsuarioRol.query.filter_by(usuario_id=id, rol_id=int(rol_id)).first()
            if existente:
                existente.es_rol_principal = True
            else:
                db.session.add(UsuarioRol(
                    usuario_id=id, rol_id=int(rol_id),
                    asignado_por=current_user.usuario_id, es_rol_principal=True
                ))
        db.session.commit()
        flash('Usuario actualizado.', 'success')
        return redirect(url_for('listar_usuarios'))
    rol_principal = UsuarioRol.query.filter_by(usuario_id=id, es_rol_principal=True).first()
    return render_template('usuarios/editar.html', usuario=usuario, roles=roles,
                           rol_principal=rol_principal)


@app.route('/usuarios/eliminar/<int:id>')
@login_required
def eliminar_usuario(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    if id == current_user.usuario_id:
        flash('No puedes desactivar tu propia cuenta.', 'danger')
        return redirect(url_for('listar_usuarios'))
    usuario = Usuario.query.get_or_404(id)
    usuario.estado = False
    db.session.commit()
    flash('Usuario desactivado.', 'success')
    return redirect(url_for('listar_usuarios'))


@app.route('/usuarios/bloquear/<int:id>')
@login_required
def bloquear_usuario(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    usuario = Usuario.query.get_or_404(id)
    usuario.cuenta_bloqueada = not usuario.cuenta_bloqueada
    usuario.intentos_login = 0
    db.session.commit()
    estado = 'bloqueada' if usuario.cuenta_bloqueada else 'desbloqueada'
    flash(f'Cuenta {estado}.', 'success')
    return redirect(url_for('listar_usuarios'))

# ---------- Gestión de Roles ----------
@app.route('/roles')
@login_required
def listar_roles():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    roles = RolDetalle.query.order_by(RolDetalle.nivel_permisos.desc()).all()
    return render_template('roles/listar.html', roles=roles)


@app.route('/roles/agregar', methods=['GET', 'POST'])
@login_required
def agregar_rol():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    permisos = Permiso.query.order_by(Permiso.modulo, Permiso.categoria).all()
    if request.method == 'POST':
        nombre = request.form['nombre_rol'].strip().lower()
        if RolDetalle.query.filter_by(nombre_rol=nombre).first():
            flash('Ese nombre de rol ya existe.', 'danger')
            return render_template('roles/agregar.html', permisos=permisos)
        nuevo = RolDetalle(
            nombre_rol=nombre,
            descripcion=request.form['descripcion'],
            nivel_permisos=int(request.form['nivel_permisos']),
            puede_crear_usuarios='puede_crear_usuarios' in request.form,
            puede_eliminar_datos='puede_eliminar_datos' in request.form,
            puede_configurar_sistema='puede_configurar_sistema' in request.form,
            acceso_total='acceso_total' in request.form,
            creado_por=current_user.usuario_id
        )
        db.session.add(nuevo)
        db.session.flush()
        # Asignar permisos seleccionados
        for pid in request.form.getlist('permisos'):
            db.session.add(RolPermiso(
                rol_id=nuevo.rol_id, permiso_id=int(pid),
                concedido_por=current_user.usuario_id
            ))
        db.session.commit()
        flash('Rol creado exitosamente.', 'success')
        return redirect(url_for('listar_roles'))
    return render_template('roles/agregar.html', permisos=permisos)


@app.route('/roles/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_rol(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    rol = RolDetalle.query.get_or_404(id)
    permisos = Permiso.query.order_by(Permiso.modulo, Permiso.categoria).all()
    permisos_asignados = {rp.permiso_id for rp in rol.permisos}
    if request.method == 'POST':
        rol.descripcion = request.form['descripcion']
        rol.nivel_permisos = int(request.form['nivel_permisos'])
        rol.puede_crear_usuarios = 'puede_crear_usuarios' in request.form
        rol.puede_eliminar_datos = 'puede_eliminar_datos' in request.form
        rol.puede_configurar_sistema = 'puede_configurar_sistema' in request.form
        rol.acceso_total = 'acceso_total' in request.form
        # Sincronizar permisos
        nuevos = {int(p) for p in request.form.getlist('permisos')}
        # Quitar los que ya no están
        for rp in list(rol.permisos):
            if rp.permiso_id not in nuevos:
                db.session.delete(rp)
        # Agregar los nuevos
        actuales = {rp.permiso_id for rp in rol.permisos}
        for pid in nuevos - actuales:
            db.session.add(RolPermiso(
                rol_id=id, permiso_id=pid,
                concedido_por=current_user.usuario_id
            ))
        db.session.commit()
        flash('Rol actualizado.', 'success')
        return redirect(url_for('listar_roles'))
    return render_template('roles/editar.html', rol=rol, permisos=permisos,
                           permisos_asignados=permisos_asignados)


@app.route('/roles/eliminar/<int:id>')
@login_required
def eliminar_rol(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    rol = RolDetalle.query.get_or_404(id)
    if rol.usuarios:
        flash('No se puede eliminar: hay usuarios con este rol.', 'danger')
        return redirect(url_for('listar_roles'))
    db.session.delete(rol)
    db.session.commit()
    flash('Rol eliminado.', 'success')
    return redirect(url_for('listar_roles'))


# ---------- Gestión de Permisos ----------
@app.route('/permisos')
@login_required
def listar_permisos():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    permisos = Permiso.query.order_by(Permiso.modulo, Permiso.categoria).all()
    return render_template('permisos/listar.html', permisos=permisos)


@app.route('/permisos/agregar', methods=['GET', 'POST'])
@login_required
def agregar_permiso():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        nombre = request.form['nombre_permiso'].strip()
        if Permiso.query.filter_by(nombre_permiso=nombre).first():
            flash('Ese permiso ya existe.', 'danger')
            return render_template('permisos/agregar.html')
        nuevo = Permiso(
            nombre_permiso=nombre,
            descripcion=request.form['descripcion'],
            categoria=request.form['categoria'],
            modulo=request.form['modulo'],
            es_critico='es_critico' in request.form
        )
        db.session.add(nuevo)
        db.session.commit()
        flash('Permiso creado.', 'success')
        return redirect(url_for('listar_permisos'))
    return render_template('permisos/agregar.html')


@app.route('/permisos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_permiso(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    permiso = Permiso.query.get_or_404(id)
    if request.method == 'POST':
        permiso.descripcion = request.form['descripcion']
        permiso.categoria = request.form['categoria']
        permiso.modulo = request.form['modulo']
        permiso.es_critico = 'es_critico' in request.form
        db.session.commit()
        flash('Permiso actualizado.', 'success')
        return redirect(url_for('listar_permisos'))
    return render_template('permisos/editar.html', permiso=permiso)


@app.route('/permisos/eliminar/<int:id>')
@login_required
def eliminar_permiso(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    permiso = Permiso.query.get_or_404(id)
    if permiso.roles:
        flash('No se puede eliminar: está asignado a roles.', 'danger')
        return redirect(url_for('listar_permisos'))
    db.session.delete(permiso)
    db.session.commit()
    flash('Permiso eliminado.', 'success')
    return redirect(url_for('listar_permisos'))

# ---------- Asignación Usuario-Rol ----------
@app.route('/usuarios/<int:id>/roles', methods=['GET', 'POST'])
@login_required
def gestionar_roles_usuario(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    usuario = Usuario.query.get_or_404(id)
    roles = RolDetalle.query.order_by(RolDetalle.nivel_permisos.desc()).all()
    if request.method == 'POST':
        accion = request.form.get('accion')
        rol_id = int(request.form['rol_id'])
        if accion == 'asignar':
            existente = UsuarioRol.query.filter_by(usuario_id=id, rol_id=rol_id).first()
            if not existente:
                db.session.add(UsuarioRol(
                    usuario_id=id, rol_id=rol_id,
                    asignado_por=current_user.usuario_id,
                    es_rol_principal=False
                ))
                db.session.commit()
                flash('Rol asignado.', 'success')
            else:
                flash('El usuario ya tiene ese rol.', 'info')
        return redirect(url_for('gestionar_roles_usuario', id=id))
    asignaciones = UsuarioRol.query.filter_by(usuario_id=id).all()
    return render_template('usuarios/roles.html', usuario=usuario,
                           roles=roles, asignaciones=asignaciones)


@app.route('/usuarios/<int:id>/roles/<int:ur_id>/quitar')
@login_required
def quitar_rol_usuario(id, ur_id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    asignacion = UsuarioRol.query.get_or_404(ur_id)
    if asignacion.es_rol_principal:
        flash('No puedes quitar el rol principal directamente.', 'danger')
        return redirect(url_for('gestionar_roles_usuario', id=id))
    db.session.delete(asignacion)
    db.session.commit()
    flash('Rol quitado.', 'success')
    return redirect(url_for('gestionar_roles_usuario', id=id))


@app.route('/usuarios/<int:id>/roles/<int:ur_id>/principal')
@login_required
def marcar_rol_principal(id, ur_id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    UsuarioRol.query.filter_by(usuario_id=id).update({'es_rol_principal': False})
    asignacion = UsuarioRol.query.get_or_404(ur_id)
    asignacion.es_rol_principal = True
    db.session.commit()
    flash('Rol principal actualizado.', 'success')
    return redirect(url_for('gestionar_roles_usuario', id=id))

# ---------- Umbrales de Alertas ----------
@app.route('/paciente/<int:paciente_id>/umbrales')
@login_required
def listar_umbrales(paciente_id):
    if not (current_user.is_admin() or current_user.is_medico()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    paciente = Usuario.query.get_or_404(paciente_id)
    umbrales = UmbralAlerta.query.filter_by(paciente_id=paciente_id).all()
    return render_template('umbrales/listar.html', paciente=paciente, umbrales=umbrales)


@app.route('/paciente/<int:paciente_id>/umbrales/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_umbral(paciente_id):
    if not (current_user.is_admin() or current_user.is_medico()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    paciente = Usuario.query.get_or_404(paciente_id)
    if request.method == 'POST':
        nuevo = UmbralAlerta(
            paciente_id=paciente_id,
            tipo_signo_vital=request.form['tipo_signo_vital'],
            minimo_normal=to_float(request.form['minimo_normal']),
            maximo_normal=to_float(request.form['maximo_normal']),
            minimo_critico=to_float(request.form['minimo_critico']),
            maximo_critico=to_float(request.form['maximo_critico']),
            configurado_por=current_user.usuario_id,
            esta_activo=True
        )
        # Validar coherencia
        if not (nuevo.minimo_normal < nuevo.maximo_normal and
                nuevo.minimo_critico <= nuevo.minimo_normal and
                nuevo.maximo_critico >= nuevo.maximo_normal):
            flash('Los umbrales no son coherentes.', 'danger')
            return render_template('umbrales/agregar.html', paciente=paciente)
        db.session.add(nuevo)
        db.session.commit()
        flash('Umbral registrado.', 'success')
        return redirect(url_for('listar_umbrales', paciente_id=paciente_id))
    return render_template('umbrales/agregar.html', paciente=paciente)


@app.route('/umbrales/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_umbral(id):
    if not (current_user.is_admin() or current_user.is_medico()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    umbral = UmbralAlerta.query.get_or_404(id)
    if request.method == 'POST':
        umbral.minimo_normal = to_float(request.form['minimo_normal'])
        umbral.maximo_normal = to_float(request.form['maximo_normal'])
        umbral.minimo_critico = to_float(request.form['minimo_critico'])
        umbral.maximo_critico = to_float(request.form['maximo_critico'])
        umbral.esta_activo = 'esta_activo' in request.form
        db.session.commit()
        flash('Umbral actualizado.', 'success')
        return redirect(url_for('listar_umbrales', paciente_id=umbral.paciente_id))
    return render_template('umbrales/editar.html', umbral=umbral)


@app.route('/umbrales/eliminar/<int:id>')
@login_required
def eliminar_umbral(id):
    if not (current_user.is_admin() or current_user.is_medico()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    umbral = UmbralAlerta.query.get_or_404(id)
    pid = umbral.paciente_id
    db.session.delete(umbral)
    db.session.commit()
    flash('Umbral eliminado.', 'success')
    return redirect(url_for('listar_umbrales', paciente_id=pid))

# ---------- Dispositivos ----------
@app.route('/paciente/<int:paciente_id>/dispositivos')
@login_required
def listar_dispositivos(paciente_id):
    if not (current_user.is_admin() or current_user.is_medico()
            or current_user.is_enfermero() or current_user.usuario_id == paciente_id):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    paciente = Usuario.query.get_or_404(paciente_id)
    dispositivos = Dispositivo.query.filter_by(paciente_id=paciente_id).all()
    return render_template('dispositivos/listar.html', paciente=paciente,
                           dispositivos=dispositivos)


@app.route('/paciente/<int:paciente_id>/dispositivos/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_dispositivo(paciente_id):
    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    paciente = Usuario.query.get_or_404(paciente_id)
    if request.method == 'POST':
        nuevo = Dispositivo(
            paciente_id=paciente_id,
            tipo_dispositivo=request.form['tipo_dispositivo'],
            marca_modelo=request.form['marca_modelo'],
            numero_serie=request.form.get('numero_serie') or None,
            esta_activo=True
        )
        db.session.add(nuevo)
        db.session.commit()
        flash('Dispositivo registrado.', 'success')
        return redirect(url_for('listar_dispositivos', paciente_id=paciente_id))
    return render_template('dispositivos/agregar.html', paciente=paciente)


@app.route('/dispositivos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_dispositivo(id):
    disp = Dispositivo.query.get_or_404(id)
    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        disp.marca_modelo = request.form['marca_modelo']
        disp.numero_serie = request.form.get('numero_serie') or None
        disp.esta_activo = 'esta_activo' in request.form
        db.session.commit()
        flash('Dispositivo actualizado.', 'success')
        return redirect(url_for('listar_dispositivos', paciente_id=disp.paciente_id))
    return render_template('dispositivos/editar.html', dispositivo=disp)


@app.route('/dispositivos/sincronizar/<int:id>')
@login_required
def sincronizar_dispositivo(id):
    if not (current_user.is_admin() or current_user.is_medico() or current_user.is_enfermero()):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    disp = Dispositivo.query.get_or_404(id)
    disp.fecha_ultima_sincronizacion = datetime.datetime.utcnow()
    db.session.commit()
    flash('Dispositivo sincronizado.', 'success')
    return redirect(url_for('listar_dispositivos', paciente_id=disp.paciente_id))


@app.route('/dispositivos/eliminar/<int:id>')
@login_required
def eliminar_dispositivo(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    disp = Dispositivo.query.get_or_404(id)
    pid = disp.paciente_id
    db.session.delete(disp)
    db.session.commit()
    flash('Dispositivo eliminado.', 'success')
    return redirect(url_for('listar_dispositivos', paciente_id=pid))

# ---------- Notificaciones ----------
@app.route('/notificaciones')
@login_required
def listar_notificaciones():
    notifs = Notificacion.query.filter_by(usuario_id=current_user.usuario_id)\
                               .order_by(Notificacion.fecha_creacion.desc()).all()
    return render_template('notificaciones/listar.html', notificaciones=notifs)


@app.route('/notificaciones/<int:id>/leer')
@login_required
def marcar_leida(id):
    n = Notificacion.query.get_or_404(id)
    if n.usuario_id != current_user.usuario_id:
        flash('No autorizado', 'danger')
        return redirect(url_for('listar_notificaciones'))
    n.leida = True
    n.fecha_leida = datetime.datetime.utcnow()
    db.session.commit()
    if n.url_destino:
        return redirect(n.url_destino)
    return redirect(url_for('listar_notificaciones'))


@app.route('/notificaciones/leer-todas')
@login_required
def marcar_todas_leidas():
    Notificacion.query.filter_by(usuario_id=current_user.usuario_id, leida=False)\
                     .update({'leida': True,
                              'fecha_leida': datetime.datetime.utcnow()})
    db.session.commit()
    flash('Todas las notificaciones marcadas como leídas.', 'success')
    return redirect(url_for('listar_notificaciones'))


# Solo admin puede crear/eliminar notificaciones del sistema
@app.route('/notificaciones/agregar', methods=['GET', 'POST'])
@login_required
def agregar_notificacion():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    usuarios = Usuario.query.filter_by(estado=True).all()
    if request.method == 'POST':
        nueva = Notificacion(
            usuario_id=int(request.form['usuario_id']),
            titulo=request.form['titulo'],
            mensaje=request.form['mensaje'],
            tipo=request.form['tipo'],
            prioridad=request.form.get('prioridad', 'media'),
            url_destino=request.form.get('url_destino') or None
        )
        db.session.add(nueva)
        db.session.commit()
        flash('Notificación enviada.', 'success')
        return redirect(url_for('listar_notificaciones'))
    return render_template('notificaciones/agregar.html', usuarios=usuarios)

# ---------- Auditoría (solo lectura) ----------
@app.route('/auditoria')
@login_required
def listar_auditoria():
    if not (current_user.is_admin() or current_user.tiene_permiso('lectura_auditoria')):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    # Filtros opcionales
    tabla = request.args.get('tabla')
    operacion = request.args.get('operacion')
    query = Auditoria.query
    if tabla:
        query = query.filter_by(tabla_afectada=tabla)
    if operacion:
        query = query.filter_by(operacion=operacion)
    registros = query.order_by(Auditoria.fecha_operacion.desc()).limit(500).all()
    return render_template('auditoria/listar.html', registros=registros,
                           tabla=tabla, operacion=operacion)


@app.route('/auditoria/detalle/<int:id>')
@login_required
def detalle_auditoria(id):
    if not (current_user.is_admin() or current_user.tiene_permiso('lectura_auditoria')):
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    registro = Auditoria.query.get_or_404(id)
    return render_template('auditoria/detalle.html', registro=registro)

# ---------- Respaldos Lógicos ----------
@app.route('/respaldos/logicos')
@login_required
def listar_respaldos_logicos():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    respaldos = RespaldoLogico.consulta_todos()
    return render_template('respaldos/logicos.html', respaldos=respaldos)


@app.route('/respaldos/logicos/crear', methods=['POST'])
@login_required
def crear_respaldo_logico():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    # Simulación: crea un registro de respaldo
    total = (Usuario.query.count() + RolDetalle.query.count()
             + Permiso.query.count() + SignoVital.query.count()
             + HistorialClinico.query.count())
    import datetime as _dt
    fecha_str = _dt.datetime.now().strftime('%Y%m%d_%H%i%s')
    nuevo = RespaldoLogico(
        usuario_id=current_user.usuario_id,
        tipo_respaldo='completo',
        tablas_incluidas='usuarios,roles_detalle,permisos,signos_vitales,historial_clinico',
        total_registros=total,
        tamaño_estimado_mb=round(total * 0.1, 2),
        ruta_archivo=f'/backups/healthguard_{fecha_str}.sql',
        estado='completado'
    )
    db.session.add(nuevo)
    # Registrar en auditoría
    db.session.flush()
    db.session.add(Auditoria(
        tabla_afectada='sistema', operacion='BACKUP',
        registro_id=nuevo.respaldo_id, usuario_id=current_user.usuario_id,
        datos_nuevos={'tipo': 'respaldo_logico', 'total_registros': total},
        nivel_severidad='info'
    ))
    db.session.commit()
    flash('Respaldo lógico creado.', 'success')
    return redirect(url_for('listar_respaldos_logicos'))


@app.route('/respaldos/logicos/eliminar/<int:id>')
@login_required
def eliminar_respaldo_logico(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    r = RespaldoLogico.query.get_or_404(id)
    db.session.delete(r)
    db.session.commit()
    flash('Registro de respaldo eliminado.', 'success')
    return redirect(url_for('listar_respaldos_logicos'))

# ---------- Respaldos Físicos ----------
@app.route('/respaldos/fisicos')
@login_required
def listar_respaldos_fisicos():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    respaldos = RespaldoFisico.consulta_todos()
    return render_template('respaldos/fisicos.html', respaldos=respaldos)


@app.route('/respaldos/fisicos/crear', methods=['POST'])
@login_required
def crear_respaldo_fisico():
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    import datetime as _dt, hashlib
    fecha_str = _dt.datetime.now().strftime('%Y%m%d_%H%i%s')
    checksum = hashlib.sha256(f'healthguard_pro{fecha_str}'.encode()).hexdigest()
    nuevo = RespaldoFisico(
        usuario_id=current_user.usuario_id,
        tipo_respaldo='completo',
        base_datos='healthguard_pro',
        tamaño_mb=245.75,
        ruta_archivo=f'/physical_backups/healthguard_{fecha_str}.bak',
        checksum=checksum,
        estado='completado',
        duracion_segundos=2
    )
    db.session.add(nuevo)
    db.session.flush()
    db.session.add(Auditoria(
        tabla_afectada='sistema', operacion='BACKUP',
        registro_id=nuevo.respaldo_id, usuario_id=current_user.usuario_id,
        datos_nuevos={'tipo': 'respaldo_fisico', 'checksum': checksum},
        nivel_severidad='info'
    ))
    db.session.commit()
    flash('Respaldo físico creado.', 'success')
    return redirect(url_for('listar_respaldos_fisicos'))


@app.route('/respaldos/fisicos/eliminar/<int:id>')
@login_required
def eliminar_respaldo_fisico(id):
    if not current_user.is_admin():
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    r = RespaldoFisico.query.get_or_404(id)
    db.session.delete(r)
    db.session.commit()
    flash('Registro de respaldo eliminado.', 'success')
    return redirect(url_for('listar_respaldos_fisicos'))




# ---------- Manejadores de error ----------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)
    
    
    