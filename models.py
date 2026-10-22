# models.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, Date, DateTime, Boolean, Text, JSON, Enum, Numeric
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

db = SQLAlchemy()

# ---------- Modelo Usuario ----------
# models.py - Reemplaza la clase Usuario completa

class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuarios'
    usuario_id = Column(Integer, primary_key=True)
    nombre = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    telefono = Column(String(20))
    direccion = Column(Text)
    codigo_postal = Column(String(10))
    genero = Column(Enum('M', 'F', 'O'))
    estado = Column(Boolean, default=True)
    fecha_creacion = Column(DateTime, default=datetime.datetime.utcnow)
    fecha_actualizacion = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    ultimo_login = Column(DateTime)
    intentos_login = Column(Integer, default=0)
    cuenta_bloqueada = Column(Boolean, default=False)

    # Relaciones - usar cascade correcto
    roles = relationship('UsuarioRol', foreign_keys='UsuarioRol.usuario_id', 
                         back_populates='usuario', cascade='all, delete-orphan', lazy='selectin')
    signos_vitales = relationship('SignoVital', foreign_keys='SignoVital.paciente_id', back_populates='paciente')
    historial_creado = relationship('HistorialClinico', foreign_keys='HistorialClinico.profesional_id', back_populates='profesional')
    historial_paciente = relationship('HistorialClinico', foreign_keys='HistorialClinico.paciente_id', back_populates='paciente')
    alertas = relationship('Alerta', foreign_keys='Alerta.paciente_id', back_populates='paciente')
    alertas_resueltas = relationship('Alerta', foreign_keys='Alerta.resuelta_por', back_populates='resolutor')
    umbrales = relationship('UmbralAlerta', foreign_keys='UmbralAlerta.paciente_id', back_populates='paciente')
    dispositivos = relationship('Dispositivo', back_populates='paciente')
    notificaciones = relationship('Notificacion', back_populates='usuario')
    signos_validados = relationship('SignoVital', foreign_keys='SignoVital.validado_por', back_populates='validador')

    @property
    def password(self):
        raise AttributeError('El password no tiene acceso de lectura')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def validar_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.usuario_id)

    def is_active(self):
        return self.estado and not self.cuenta_bloqueada

    def _get_rol_principal(self):
        """Obtiene el nombre del rol principal de forma segura."""
        try:
            for ur in self.roles:
                if ur.es_rol_principal and ur.rol is not None:
                    return ur.rol.nombre_rol
        except Exception:
            return None
        return None

    def is_admin(self):
        rol = self._get_rol_principal()
        return rol == 'administrador_sistema'

    def is_medico(self):
        rol = self._get_rol_principal()
        return rol is not None and rol.startswith('medico')

    def is_enfermero(self):
        rol = self._get_rol_principal()
        return rol is not None and rol.startswith('enfermero')

    def is_paciente(self):
        rol = self._get_rol_principal()
        return rol is not None and rol.startswith('paciente')

    def tiene_permiso(self, nombre_permiso):
        for ur in self.roles:
            if ur.fecha_expiracion and ur.fecha_expiracion < datetime.datetime.utcnow():
                continue
            if ur.rol is None:
                continue
            for rp in ur.rol.permisos:
                if rp.fecha_expiracion and rp.fecha_expiracion < datetime.datetime.utcnow():
                    continue
                if rp.permiso and rp.permiso.nombre_permiso == nombre_permiso:
                    return True
        return False

    def agregar(self):
        db.session.add(self)
        db.session.commit()

    def editar(self):
        db.session.merge(self)
        db.session.commit()

    def eliminar(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def consulta_individual(cls, id):
        return cls.query.get(id)

    @classmethod
    def consulta_activos(cls):
        return cls.query.filter_by(estado=True).all()

    @classmethod
    def validar(cls, email, password):
        """
        Valida credenciales y gestiona intentos fallidos / bloqueo de cuenta.
        Retorna el usuario si las credenciales son válidas, None en caso contrario.
        """
        # Buscar usuario por email (aunque esté inactivo, para poder auditar)
        usuario = cls.query.filter_by(email=email).first()
    
        # Caso 1: el usuario no existe
        if not usuario:
            return None
    
        # Caso 2: la cuenta está desactivada (estado=False)
        if not usuario.estado:
            return None
    
        # Caso 3: la cuenta está bloqueada por intentos fallidos
        if usuario.cuenta_bloqueada:
            return None
    
        # Caso 4: contraseña correcta -> reiniciar contador
        if usuario.validar_password(password):
            usuario.intentos_login = 0
            db.session.commit()
            return usuario
    
        # Caso 5: contraseña incorrecta -> incrementar intentos y bloquear si llega al límite
        usuario.intentos_login = (usuario.intentos_login or 0) + 1
        if usuario.intentos_login >= 5:
            usuario.cuenta_bloqueada = True
        db.session.commit()
        return None
    
# ---------- Modelo RolDetalle ----------
class RolDetalle(db.Model):
    __tablename__ = 'roles_detalle'
    rol_id = Column(Integer, primary_key=True)
    nombre_rol = Column(String(50), unique=True, nullable=False)
    descripcion = Column(Text, nullable=False)
    nivel_permisos = Column(Integer, nullable=False)  # 1-10
    puede_crear_usuarios = Column(Boolean, default=False)
    puede_eliminar_datos = Column(Boolean, default=False)
    puede_configurar_sistema = Column(Boolean, default=False)
    acceso_total = Column(Boolean, default=False)
    fecha_creacion = Column(DateTime, default=datetime.datetime.utcnow)
    creado_por = Column(Integer, db.ForeignKey('usuarios.usuario_id'))

    # Relaciones
    creador = relationship('Usuario', foreign_keys=[creado_por])
    usuarios = relationship('UsuarioRol', back_populates='rol')
    permisos = relationship('RolPermiso', back_populates='rol',lazy='selectin')  # <-- AGREGAR lazy='selectin' para optimizar la carga de permisos


# ---------- Modelo Permiso ----------
class Permiso(db.Model):
    __tablename__ = 'permisos'
    permiso_id = Column(Integer, primary_key=True)
    nombre_permiso = Column(String(100), unique=True, nullable=False)
    descripcion = Column(Text, nullable=False)
    categoria = Column(Enum('lectura', 'escritura', 'eliminacion', 'administracion'), nullable=False)
    modulo = Column(String(50), nullable=False)
    es_critico = Column(Boolean, default=False)

    roles = relationship('RolPermiso', back_populates='permiso')


# ---------- Modelo RolPermiso (asignación) ----------
class RolPermiso(db.Model):
    __tablename__ = 'rol_permisos'
    rol_permiso_id = Column(Integer, primary_key=True)
    rol_id = Column(Integer, db.ForeignKey('roles_detalle.rol_id'), nullable=False)
    permiso_id = Column(Integer, db.ForeignKey('permisos.permiso_id'), nullable=False)
    concedido_por = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    fecha_concesion = Column(DateTime, default=datetime.datetime.utcnow)
    fecha_expiracion = Column(DateTime)

    rol = relationship('RolDetalle', back_populates='permisos')
    permiso = relationship('Permiso', back_populates='roles',lazy='joined')  # <-- AGREGAR lazy='joined' para optimizar la carga de permisos
    concedente = relationship('Usuario', foreign_keys=[concedido_por])


# ---------- Modelo UsuarioRol ----------
# En UsuarioRol:
class UsuarioRol(db.Model):
    __tablename__ = 'usuario_roles'
    usuario_rol_id = Column(Integer, primary_key=True)
    usuario_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    rol_id = Column(Integer, db.ForeignKey('roles_detalle.rol_id'), nullable=False)
    asignado_por = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    fecha_asignacion = Column(DateTime, default=datetime.datetime.utcnow)
    fecha_expiracion = Column(DateTime)
    es_rol_principal = Column(Boolean, default=False)

    usuario = relationship('Usuario', foreign_keys=[usuario_id], back_populates='roles')
    rol = relationship('RolDetalle', back_populates='usuarios', lazy='joined')  # <-- AGREGAR lazy='joined'
    asignante = relationship('Usuario', foreign_keys=[asignado_por])


# ---------- Modelo SignoVital ----------
class SignoVital(db.Model):
    __tablename__ = 'signos_vitales'
    signo_vital_id = Column(Integer, primary_key=True)
    paciente_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    glucosa = Column(Numeric(5,2))
    presion_sistolica = Column(Integer)
    presion_diastolica = Column(Integer)
    peso = Column(Numeric(5,2))
    frecuencia_cardiaca = Column(Integer)
    oxigenacion = Column(Numeric(5,2))
    tipo_registro = Column(Enum('automatico', 'manual'), nullable=False)
    fecha_registro = Column(DateTime, default=datetime.datetime.utcnow)
    validado_por = Column(Integer, db.ForeignKey('usuarios.usuario_id'))
    fecha_validacion = Column(DateTime)
    observaciones = Column(Text)

    paciente = relationship('Usuario', foreign_keys=[paciente_id], back_populates='signos_vitales')
    validador = relationship('Usuario', foreign_keys=[validado_por])

    def agregar(self):
        db.session.add(self)
        db.session.commit()

    def editar(self):
        db.session.merge(self)
        db.session.commit()

    @classmethod
    def consulta_por_paciente(cls, paciente_id):
        return cls.query.filter_by(paciente_id=paciente_id).order_by(cls.fecha_registro.desc()).all()

    @classmethod
    def consulta_individual(cls, id):
        return cls.query.get(id)


# ---------- Modelo Alerta ----------
class Alerta(db.Model):
    __tablename__ = 'alertas'
    alerta_id = Column(Integer, primary_key=True)
    paciente_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    tipo_signo_vital = Column(Enum('glucosa', 'presion_arterial', 'peso', 'frecuencia_cardiaca', 'oxigenacion'), nullable=False)
    valor_registrado = Column(Numeric(8,2), nullable=False)
    nivel_urgencia = Column(Enum('normal', 'alerta', 'critico'), nullable=False)
    mensaje = Column(Text, nullable=False)
    fecha_generacion = Column(DateTime, default=datetime.datetime.utcnow)
    fecha_resolucion = Column(DateTime)
    resuelta_por = Column(Integer, db.ForeignKey('usuarios.usuario_id'))
    estado = Column(Enum('activa', 'en_proceso', 'resuelta', 'falsa_alarma'), default='activa')
    accion_tomada = Column(Text)

    paciente = relationship('Usuario', foreign_keys=[paciente_id], back_populates='alertas')
    resolutor = relationship('Usuario', foreign_keys=[resuelta_por], back_populates='alertas_resueltas')

    def agregar(self):
        db.session.add(self)
        db.session.commit()

    def editar(self):
        db.session.merge(self)
        db.session.commit()

    @classmethod
    def consulta_activas(cls):
        return cls.query.filter_by(estado='activa').order_by(cls.fecha_generacion.desc()).all()

    @classmethod
    def consulta_por_paciente(cls, paciente_id):
        return cls.query.filter_by(paciente_id=paciente_id).order_by(cls.fecha_generacion.desc()).all()


# ---------- Modelo HistorialClinico ----------
class HistorialClinico(db.Model):
    __tablename__ = 'historial_clinico'
    historial_id = Column(Integer, primary_key=True)
    paciente_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    tipo_entrada = Column(Enum('diagnostico', 'medicamento', 'antecedente', 'laboratorio', 'evolucion'), nullable=False)
    titulo = Column(String(200), nullable=False)
    descripcion = Column(Text)
    archivo_url = Column(String(500))
    profesional_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    fecha_creacion = Column(DateTime, default=datetime.datetime.utcnow)
    fecha_actualizacion = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    es_urgente = Column(Boolean, default=False)
    categoria = Column(String(100))
    nivel_confidencialidad = Column(Enum('bajo', 'medio', 'alto', 'critico'), default='medio')

    paciente = relationship('Usuario', foreign_keys=[paciente_id], back_populates='historial_paciente')
    profesional = relationship('Usuario', foreign_keys=[profesional_id], back_populates='historial_creado')

    def agregar(self):
        db.session.add(self)
        db.session.commit()

    def editar(self):
        db.session.merge(self)
        db.session.commit()

    @classmethod
    def consulta_por_paciente(cls, paciente_id):
        return cls.query.filter_by(paciente_id=paciente_id).order_by(cls.fecha_creacion.desc()).all()


# ---------- Modelo UmbralAlerta (opcional, no se usará en este ejemplo básico) ----------
class UmbralAlerta(db.Model):
    __tablename__ = 'umbrales_alertas'
    umbral_id = Column(Integer, primary_key=True)
    paciente_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    tipo_signo_vital = Column(Enum('glucosa', 'presion_arterial', 'peso', 'frecuencia_cardiaca', 'oxigenacion'), nullable=False)
    minimo_normal = Column(Numeric(8,2), nullable=False)
    maximo_normal = Column(Numeric(8,2), nullable=False)
    minimo_critico = Column(Numeric(8,2), nullable=False)
    maximo_critico = Column(Numeric(8,2), nullable=False)
    configurado_por = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    fecha_configuracion = Column(DateTime, default=datetime.datetime.utcnow)
    esta_activo = Column(Boolean, default=True)

    paciente = relationship('Usuario', foreign_keys=[paciente_id], back_populates='umbrales')
    configurador = relationship('Usuario', foreign_keys=[configurado_por])

class Dispositivo(db.Model):
    __tablename__ = 'dispositivos'
    dispositivo_id = Column(Integer, primary_key=True)
    paciente_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    tipo_dispositivo = Column(Enum('glucometro', 'tensiometro', 'balanza', 'oximetro', 'pulsometro'), nullable=False)
    marca_modelo = Column(String(100), nullable=False)
    numero_serie = Column(String(100), unique=True)
    fecha_activacion = Column(DateTime, default=datetime.datetime.utcnow)
    fecha_ultima_sincronizacion = Column(DateTime)
    esta_activo = Column(Boolean, default=True)
    configuracion = Column(JSON)

    # Relación inversa con Usuario
    paciente = relationship('Usuario', foreign_keys=[paciente_id], back_populates='dispositivos')
# ... otros modelos (Dispositivo, Notificacion, Auditoria, Respaldos) pueden agregarse si es necesario.

class Notificacion(db.Model):
    __tablename__ = 'notificaciones'
    notificacion_id = Column(Integer, primary_key=True)
    usuario_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    titulo = Column(String(200), nullable=False)
    mensaje = Column(Text, nullable=False)
    tipo = Column(Enum('alerta', 'recordatorio', 'sistema', 'general'), nullable=False)
    leida = Column(Boolean, default=False)
    fecha_creacion = Column(DateTime, default=datetime.datetime.utcnow)
    fecha_leida = Column(DateTime)
    url_destino = Column(String(500))
    prioridad = Column(Enum('baja', 'media', 'alta', 'urgente'), default='media')

    usuario = relationship('Usuario', back_populates='notificaciones')
    
    # ---------- Modelo Auditoria ----------
class Auditoria(db.Model):
    __tablename__ = 'auditoria'
    auditoria_id = Column(Integer, primary_key=True)
    tabla_afectada = Column(String(50), nullable=False)
    operacion = Column(Enum('INSERT', 'UPDATE', 'DELETE', 'BACKUP', 'RESTORE'), nullable=False)
    registro_id = Column(Integer, nullable=False)
    usuario_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    datos_anteriores = Column(JSON)
    datos_nuevos = Column(JSON)
    fecha_operacion = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    nivel_severidad = Column(Enum('info', 'advertencia', 'error', 'critico'), default='info')

    usuario = relationship('Usuario', foreign_keys=[usuario_id])

    @classmethod
    def consulta_reciente(cls, limite=100):
        return cls.query.order_by(cls.fecha_operacion.desc()).limit(limite).all()

    @classmethod
    def consulta_por_usuario(cls, usuario_id):
        return cls.query.filter_by(usuario_id=usuario_id).order_by(cls.fecha_operacion.desc()).all()


# ---------- Modelo RespaldoLogico ----------
class RespaldoLogico(db.Model):
    __tablename__ = 'respaldos_logicos'
    respaldo_id = Column(Integer, primary_key=True)
    fecha_respaldo = Column(DateTime, default=datetime.datetime.utcnow)
    usuario_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    tipo_respaldo = Column(Enum('completo', 'parcial', 'incremental'), default='completo')
    tablas_incluidas = Column(Text)
    total_registros = Column(Integer)
    tamaño_estimado_mb = Column(Numeric(10, 2))
    ruta_archivo = Column(String(500))
    estado = Column(Enum('en_proceso', 'completado', 'fallido'), default='en_proceso')

    usuario = relationship('Usuario', foreign_keys=[usuario_id])

    def agregar(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def consulta_todos(cls):
        return cls.query.order_by(cls.fecha_respaldo.desc()).all()


# ---------- Modelo RespaldoFisico ----------
class RespaldoFisico(db.Model):
    __tablename__ = 'respaldos_fisicos'
    respaldo_id = Column(Integer, primary_key=True)
    fecha_respaldo = Column(DateTime, default=datetime.datetime.utcnow)
    usuario_id = Column(Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    tipo_respaldo = Column(Enum('completo', 'diferencial', 'transaccional'), default='completo')
    base_datos = Column(String(100), default='healthguard_pro')
    tamaño_mb = Column(Numeric(10, 2))
    ruta_archivo = Column(String(500))
    checksum = Column(String(64))
    estado = Column(Enum('en_proceso', 'completado', 'fallido'), default='en_proceso')
    duracion_segundos = Column(Integer)

    usuario = relationship('Usuario', foreign_keys=[usuario_id])

    def agregar(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def consulta_todos(cls):
        return cls.query.order_by(cls.fecha_respaldo.desc()).all()