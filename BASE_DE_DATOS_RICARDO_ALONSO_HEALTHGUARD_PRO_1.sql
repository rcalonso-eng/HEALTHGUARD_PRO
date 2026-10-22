-- ######################################################################################
-- # HealthGuard_Pro_MySQL8 
-- # Sistema de Monitoreo Médico Inteligente con Gestión de Roles, Permisos y Respaldos
-- # Autor: Ricardo Cesar Alonso Bravo
-- ######################################################################################

-- =============================================
-- INICIALIZACIÓN DE LA BASE DE DATOS
-- =============================================
DROP DATABASE IF EXISTS healthguard_pro;       -- Descomentar para reiniciar la DB

CREATE DATABASE IF NOT EXISTS healthguard_pro 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE healthguard_pro;

-- =============================================
-- 1. TABLA DE USUARIOS PRINCIPAL
-- Propósito: Almacena la información de acceso y personal de todos los usuarios del sistema. (Personal medico, administradores y pacientes)
-- =============================================
CREATE TABLE usuarios (
    usuario_id INT PRIMARY KEY AUTO_INCREMENT,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Almacena el hash(secuencia alfanumerica)  de la contraseña.
    telefono VARCHAR(20),
    direccion TEXT,
    codigo_postal VARCHAR(10),
    genero ENUM('M', 'F', 'O', 'NB', 'PNS') DEFAULT NULL,
    estado BOOLEAN DEFAULT TRUE, -- TRUE si la cuenta está activa.
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    ultimo_login DATETIME,
    intentos_login INT DEFAULT 0, -- Contador de intentos fallidos de inicio de sesión.
    cuenta_bloqueada BOOLEAN DEFAULT FALSE, -- Bandera para el bloqueo de seguridad.
    
    INDEX idx_usuarios_estado (estado),
    INDEX idx_usuarios_email (email),
    INDEX idx_usuarios_bloqueada (cuenta_bloqueada)
    
);

-- =============================================
-- 2. TABLA DE ROLES DETALLADOS ( Define los roles jerarquicos del sistema (Administrador, Director, Medico, Paciente ) Utiliza un nivel de permisos(1 a 10) y banderas para acciones criticas
-- (acceso total, puede eliminar datos)
-- =============================================
CREATE TABLE roles_detalle (
    rol_id INT PRIMARY KEY AUTO_INCREMENT,
    nombre_rol VARCHAR(50) UNIQUE NOT NULL,
    descripcion TEXT NOT NULL,
    nivel_permisos INT NOT NULL CHECK (nivel_permisos BETWEEN 1 AND 10), -- Nivel jerárquico (10 = más alto).
    puede_crear_usuarios BOOLEAN DEFAULT FALSE,
    puede_eliminar_datos BOOLEAN DEFAULT FALSE,
    puede_configurar_sistema BOOLEAN DEFAULT FALSE,
    acceso_total BOOLEAN DEFAULT FALSE, -- Bandera para acceso de superusuario.
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    creado_por INT,
    
    INDEX idx_roles_nivel (nivel_permisos),
    INDEX idx_roles_acceso (acceso_total)
);

-- =============================================
-- 3. TABLA DE PERMISOS ( Lista de acciones especificas que se pueden hacer en el sistema, se clasifican por categoria (lectura, escritura, eliminacion, administracion) y modulo (ej: historial clinico, respaldos)))
-- =============================================
CREATE TABLE permisos (
    permiso_id INT PRIMARY KEY AUTO_INCREMENT,
    nombre_permiso VARCHAR(100) UNIQUE NOT NULL,
    descripcion TEXT NOT NULL,
    categoria ENUM('lectura', 'escritura', 'eliminacion', 'administracion') NOT NULL, -- Tipo de operación.
    modulo VARCHAR(50) NOT NULL, -- Módulo del sistema afectado (ej. historial_clinico, respaldos).
    es_critico BOOLEAN DEFAULT FALSE, -- Indica si el permiso tiene implicaciones de seguridad o privacidad.
    
    INDEX idx_permisos_categoria (categoria),
    INDEX idx_permisos_modulo (modulo),
    INDEX idx_permisos_critico (es_critico)
);

-- =============================================
-- 4. TABLA DE ASIGNACIÓN ROL-PERMISO (N:M). Asigna los permisos a cada rol-detalle definiendo que puede hacer un rol. Permite definir la fecha de expiracion para permisos temporales.
-- =============================================
CREATE TABLE rol_permisos (
    rol_permiso_id INT PRIMARY KEY AUTO_INCREMENT,
    rol_id INT NOT NULL,
    permiso_id INT NOT NULL,
    concedido_por INT NOT NULL, -- ID del usuario que otorgó el permiso.
    fecha_concesion DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_expiracion DATETIME,
    
    UNIQUE INDEX idx_rol_permiso_unique (rol_id, permiso_id),
    INDEX idx_rol_permisos_expiracion (fecha_expiracion)
);

-- =============================================
-- 5. TABLA DE ASIGNACIÓN USUARIO-ROL (N:M). Asigna uno o mas roles_detalle a un usuario. Incluye la bandera  es_rol_principal para identificar el rol primario del usuario
-- =============================================
CREATE TABLE usuario_roles (
    usuario_rol_id INT PRIMARY KEY AUTO_INCREMENT,
    usuario_id INT NOT NULL,
    rol_id INT NOT NULL,
    asignado_por INT NOT NULL, -- ID del usuario que realizó la asignación.
    fecha_asignacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_expiracion DATETIME,
    es_rol_principal BOOLEAN DEFAULT FALSE, -- Indica el rol primario del usuario.
    
    UNIQUE INDEX idx_usuario_rol_unique (usuario_id, rol_id),
    INDEX idx_usuario_roles_expiracion (fecha_expiracion),
    INDEX idx_usuario_roles_principal (es_rol_principal)
);
-- TERMINA SEGURIDAD Y ACCESO


-- EMPIEZA DATOS CLINICOS Y MONITOREO
-- =============================================
-- 6. TABLAS DE DATOS CLÍNICOS
-- =============================================

-- Tabla: SIGNOS_VITALES. Almacena registros de salud del paciente. Incluye campos para glucosa, presion sistolica/diastolica, peso, frecuencia cardiaca,oxigenacion. Posee una restriccion (CHECK) para asegurar
-- que al menos un signo temga valor

CREATE TABLE signos_vitales (
    signo_vital_id INT PRIMARY KEY AUTO_INCREMENT,
    paciente_id INT NOT NULL,
    glucosa DECIMAL(5,2) CHECK (glucosa BETWEEN 50 AND 400 OR glucosa IS NULL),
    presion_sistolica INT CHECK (presion_sistolica BETWEEN 50 AND 250 OR presion_sistolica IS NULL),
    presion_diastolica INT CHECK (presion_diastolica BETWEEN 30 AND 150 OR presion_diastolica IS NULL),
    peso DECIMAL(5,2) CHECK (peso BETWEEN 20 AND 300 OR peso IS NULL),
    frecuencia_cardiaca INT CHECK (frecuencia_cardiaca BETWEEN 30 AND 200 OR frecuencia_cardiaca IS NULL),
    oxigenacion DECIMAL(5,2) CHECK (oxigenacion BETWEEN 50 AND 100 OR oxigenacion IS NULL),
    tipo_registro ENUM('automatico', 'manual') NOT NULL, -- Origen del dato.
    fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP,
    validado_por INT, -- ID del profesional que validó el registro.
    fecha_validacion DATETIME,
    observaciones TEXT,
    
    INDEX idx_signos_paciente_fecha (paciente_id, fecha_registro),
    INDEX idx_signos_fecha (fecha_registro),
    INDEX idx_signos_tipo (tipo_registro),
    
    -- Restricción para asegurar que al menos un signo vital tenga un valor.
    CONSTRAINT chk_al_menos_un_signo CHECK (
        glucosa IS NOT NULL OR 
        presion_sistolica IS NOT NULL OR 
        peso IS NOT NULL OR 
        frecuencia_cardiaca IS NOT NULL OR 
        oxigenacion IS NOT NULL
    )
);

-- Tabla: HISTORIAL_CLINICO. Registra el expediente clinico del paciente. Entradas tipificadas por tipo entrada ( diagnostico, medicamento, antecedente, etc ) con profesional_id como el responsable

CREATE TABLE historial_clinico (
    historial_id INT PRIMARY KEY AUTO_INCREMENT,
    paciente_id INT NOT NULL,
    tipo_entrada ENUM('diagnostico', 'medicamento', 'antecedente', 'laboratorio', 'evolucion') NOT NULL,
    titulo VARCHAR(200) NOT NULL,
    descripcion TEXT,
    archivo_url VARCHAR(500),
    profesional_id INT NOT NULL, -- ID del médico o enfermero que creó la entrada.
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    es_urgente BOOLEAN DEFAULT FALSE,
    categoria VARCHAR(100),
    nivel_confidencialidad ENUM('bajo', 'medio', 'alto', 'critico') DEFAULT 'medio',
    
    INDEX idx_historial_paciente (paciente_id),
    INDEX idx_historial_tipo (tipo_entrada),
    INDEX idx_historial_fecha (fecha_creacion),
    INDEX idx_historial_profesional (profesional_id),
    INDEX idx_historial_urgente (es_urgente),
    INDEX idx_historial_confidencialidad (nivel_confidencialidad)
);

-- Tabla: ALERTAS. Registra eventos de salud que superan los umbrales normales, Incluye tipo_signo_vital, nivel urgencia ( normal, alerta, critico) y un campo para el usuario que la resuelta_por
CREATE TABLE alertas (
    alerta_id INT PRIMARY KEY AUTO_INCREMENT,
    paciente_id INT NOT NULL,
    tipo_signo_vital ENUM('glucosa', 'presion_arterial', 'peso', 'frecuencia_cardiaca', 'oxigenacion') NOT NULL,
    valor_registrado DECIMAL(8,2) NOT NULL,
    nivel_urgencia ENUM('normal', 'alerta', 'critico') NOT NULL,
    mensaje TEXT NOT NULL,
    fecha_generacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_resolucion DATETIME,
    resuelta_por INT, -- ID del usuario que marcó la alerta como resuelta.
    estado ENUM('activa', 'en_proceso', 'resuelta', 'falsa_alarma') DEFAULT 'activa',
    accion_tomada TEXT,
    
    INDEX idx_alertas_paciente (paciente_id),
    INDEX idx_alertas_urgencia (nivel_urgencia),
    INDEX idx_alertas_estado (estado),
    INDEX idx_alertas_fecha_generacion (fecha_generacion),
    INDEX idx_alertas_tipo_signo (tipo_signo_vital)
);

-- Tabla: UMBRALES_ALERTAS. Permite definir rangos normales y criticos para los signos vitales a nivel paciente, Asegura la coherencia con una restrccion CHECK, minimo normal < maximo normal 
CREATE TABLE umbrales_alertas (
    umbral_id INT PRIMARY KEY AUTO_INCREMENT,
    paciente_id INT NOT NULL,
    tipo_signo_vital ENUM('glucosa', 'presion_arterial', 'peso', 'frecuencia_cardiaca', 'oxigenacion') NOT NULL,
    minimo_normal DECIMAL(8,2) NOT NULL,
    maximo_normal DECIMAL(8,2) NOT NULL,
    minimo_critico DECIMAL(8,2) NOT NULL,
    maximo_critico DECIMAL(8,2) NOT NULL,
    configurado_por INT NOT NULL,
    fecha_configuracion DATETIME DEFAULT CURRENT_TIMESTAMP,
    esta_activo BOOLEAN DEFAULT TRUE,
    
    UNIQUE INDEX idx_umbrales_unique (paciente_id, tipo_signo_vital, esta_activo),
    INDEX idx_umbrales_paciente (paciente_id),
    INDEX idx_umbrales_tipo (tipo_signo_vital),
    INDEX idx_umbrales_activo (esta_activo),
    
    -- Restricción para asegurar la coherencia lógica de los umbrales.
    CONSTRAINT chk_umbrales_validos CHECK (
        minimo_normal < maximo_normal AND
        minimo_critico <= minimo_normal AND
        maximo_critico >= maximo_normal
    )
);

-- Tabla: AUDITORIA. Log de todas las operaciones (INSERT, UPDATE, DELETE, BACKUP, RESTORE ) en tablas criticas. Registra la tabla_afectada, el usuario_id, y utiliza JSON para almacenar datos_anteriores y datos_nuevos
-- lo que permite un seguimineto completo 
CREATE TABLE auditoria (
    auditoria_id INT PRIMARY KEY AUTO_INCREMENT,
    tabla_afectada VARCHAR(50) NOT NULL,
    operacion ENUM('INSERT', 'UPDATE', 'DELETE', 'BACKUP', 'RESTORE') NOT NULL, -- Se amplía para incluir operaciones de respaldo.
    registro_id INT NOT NULL, -- ID del registro afectado en la tabla_afectada.
    usuario_id INT NOT NULL, -- ID del usuario que realizó la operación.
    datos_anteriores JSON, -- Valores de la fila antes de la operación (para UPDATE/DELETE).
    datos_nuevos JSON, -- Valores de la fila después de la operación (para INSERT/UPDATE).
    fecha_operacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    nivel_severidad ENUM('info', 'advertencia', 'error', 'critico') DEFAULT 'info',
    
    INDEX idx_auditoria_tabla (tabla_afectada),
    INDEX idx_auditoria_operacion (operacion),
    INDEX idx_auditoria_usuario (usuario_id),
    INDEX idx_auditoria_fecha (fecha_operacion),
    INDEX idx_auditoria_registro (registro_id),
    INDEX idx_auditoria_severidad (nivel_severidad)
);

-- Tabla: NOTIFICACIONES. Almacena mensajes dirigidos a usuarios. Clasificadas por tipo ( alerta, recordatorio, sistema y prioridad )
CREATE TABLE notificaciones (
    notificacion_id INT PRIMARY KEY AUTO_INCREMENT,
    usuario_id INT NOT NULL,
    titulo VARCHAR(200) NOT NULL,
    mensaje TEXT NOT NULL,
    tipo ENUM('alerta', 'recordatorio', 'sistema', 'general') NOT NULL,
    leida BOOLEAN DEFAULT FALSE,
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_leida DATETIME,
    url_destino VARCHAR(500),
    prioridad ENUM('baja', 'media', 'alta', 'urgente') DEFAULT 'media',
    
    INDEX idx_notificaciones_usuario (usuario_id),
    INDEX idx_notificaciones_leida (leida),
    INDEX idx_notificaciones_fecha (fecha_creacion),
    INDEX idx_notificaciones_prioridad (prioridad)
);

-- Tabla: DISPOSITIVOS
CREATE TABLE dispositivos (
    dispositivo_id INT PRIMARY KEY AUTO_INCREMENT,
    paciente_id INT NOT NULL,
    tipo_dispositivo ENUM('glucometro', 'tensiometro', 'balanza', 'oximetro', 'pulsometro') NOT NULL,
    marca_modelo VARCHAR(100) NOT NULL,
    numero_serie VARCHAR(100) UNIQUE,
    fecha_activacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    fecha_ultima_sincronizacion DATETIME,
    esta_activo BOOLEAN DEFAULT TRUE,
    configuracion JSON, -- Almacena parámetros específicos del dispositivo en formato JSON.
    
    INDEX idx_dispositivos_paciente (paciente_id),
    INDEX idx_dispositivos_activo (esta_activo),
    INDEX idx_dispositivos_tipo (tipo_dispositivo)
);

-- =============================================
-- 7. TABLAS PARA SISTEMA DE RESPALDOS (LOGS)
-- =============================================

-- Tabla para respaldos lógicos. Logs de los respaldos de datos ( exportaciones, SQL, Logicas ). Registra la ruta_archivo, el estado ( completado, en proceso, fallido) y el total registros respaldados
CREATE TABLE IF NOT EXISTS respaldos_logicos (
    respaldo_id INT PRIMARY KEY AUTO_INCREMENT,
    fecha_respaldo DATETIME DEFAULT CURRENT_TIMESTAMP,
    usuario_id INT NOT NULL,
    tipo_respaldo ENUM('completo', 'parcial', 'incremental') DEFAULT 'completo',
    tablas_incluidas TEXT,
    total_registros INT,
    tamaño_estimado_mb DECIMAL(10,2),
    ruta_archivo VARCHAR(500),
    estado ENUM('en_proceso', 'completado', 'fallido') DEFAULT 'en_proceso',
    
    INDEX idx_resp_logicos_fecha (fecha_respaldo),
    INDEX idx_resp_logicos_estado (estado)
);

-- Tabla para respaldos físicos. Logs de los respaldos de la base de datos completa a nivel de sistema de archivos. Incluye tamaño_mb, un checksum(SHA2) para la verificacion de integridad y la duracion_segundos del proceso
CREATE TABLE IF NOT EXISTS respaldos_fisicos (
    respaldo_id INT PRIMARY KEY AUTO_INCREMENT,
    fecha_respaldo DATETIME DEFAULT CURRENT_TIMESTAMP,
    usuario_id INT NOT NULL,
    tipo_respaldo ENUM('completo', 'diferencial', 'transaccional') DEFAULT 'completo',
    base_datos VARCHAR(100) DEFAULT 'healthguard_pro',
    tamaño_mb DECIMAL(10,2),
    ruta_archivo VARCHAR(500),
    checksum VARCHAR(64), -- Código de verificación para asegurar la integridad del archivo.
    estado ENUM('en_proceso', 'completado', 'fallido') DEFAULT 'en_proceso',
    duracion_segundos INT,
    
    INDEX idx_resp_fisicos_fecha (fecha_respaldo),
    INDEX idx_resp_fisicos_estado (estado)
);

-- =============================================
-- 8. INSERCIÓN DE DATOS DE PRUEBA 
-- =============================================

-- 8.1 PRIMERO: Insertar usuarios básicos 
INSERT INTO usuarios (nombre, email, password_hash, telefono,genero,estado) VALUES
('Admin Principal', 'admin@hospital.com', '$2b$10$ExampleHash12345678901234567890', '+1234567890',NULL,TRUE),
-- ('Admin Principal', 'admin@hospital.com', 'pbkdf2:sha256:260000$jRzX7s9k$8a2f3d1e5b7c9a0b2d4f6e8a1c3b5d7e9f0a2b4c6d8e0f1a2b3c4d5e6f7a8b9c', '+1234567890', TRUE),
('Admin Soporte', 'soporte@hospital.com', '$2b$10$ExampleHash12345678901234567891', '+1234567891',NULL, TRUE);

-- 8.2 SEGUNDO: Insertar roles detallados
INSERT INTO roles_detalle (nombre_rol, descripcion, nivel_permisos, puede_crear_usuarios, puede_eliminar_datos, puede_configurar_sistema, acceso_total, creado_por) VALUES
('administrador_sistema', 'Control total del sistema, configuración y administración de usuarios', 10, TRUE, TRUE, TRUE, TRUE, 1),
('director_medico', 'Máxima autoridad médica, acceso a todos los datos clínicos', 9, TRUE, FALSE, TRUE, FALSE, 1),
('medico_especialista', 'Médico con acceso completo a datos de pacientes asignados', 7, FALSE, FALSE, FALSE, FALSE, 1),
('medico_general', 'Médico con acceso limitado a funcionalidades básicas', 6, FALSE, FALSE, FALSE, FALSE, 1),
('enfermero_jefe', 'Enfermero con permisos extendidos y supervisión', 5, FALSE, FALSE, FALSE, FALSE, 1),
('enfermero', 'Enfermero con permisos básicos de registro y monitoreo', 4, FALSE, FALSE, FALSE, FALSE, 1),
('paciente_avanzado', 'Paciente con acceso extendido a sus datos', 3, FALSE, FALSE, FALSE, FALSE, 1),
('paciente', 'Paciente con acceso básico a su información', 2, FALSE, FALSE, FALSE, FALSE, 1),
('invitado', 'Acceso limitado de solo lectura a información pública', 1, FALSE, FALSE, FALSE, FALSE, 1);

-- 8.3 TERCERO: Insertar permisos del sistema
INSERT INTO permisos (nombre_permiso, descripcion, categoria, modulo, es_critico) VALUES
('admin_sistema', 'Administración completa del sistema', 'administracion', 'sistema', TRUE),
('gestion_usuarios', 'Crear, modificar y eliminar usuarios', 'administracion', 'usuarios', TRUE),
('gestion_roles', 'Gestionar roles y permisos', 'administracion', 'seguridad', TRUE),
('configuracion_sistema', 'Configurar parámetros del sistema', 'administracion', 'sistema', TRUE),
('lectura_historial_completo', 'Leer historial clínico completo', 'lectura', 'historial_clinico', TRUE),
('escritura_historial', 'Escribir en historial clínico', 'escritura', 'historial_clinico', TRUE),
('lectura_signos_vitales', 'Leer signos vitales', 'lectura', 'monitoreo', FALSE),
('escritura_signos_vitales', 'Registrar signos vitales', 'escritura', 'monitoreo', FALSE),
('validacion_signos_vitales', 'Validar signos vitales', 'escritura', 'monitoreo', FALSE),
('lectura_alertas', 'Ver alertas del sistema', 'lectura', 'alertas', FALSE),
('gestion_alertas', 'Gestionar y resolver alertas', 'escritura', 'alertas', FALSE),
('configuracion_umbrales', 'Configurar umbrales de alertas', 'administracion', 'alertas', TRUE),
('gestion_dispositivos', 'Gestionar dispositivos médicos', 'administracion', 'dispositivos', FALSE),
('sincronizacion_dispositivos', 'Sincronizar datos de dispositivos', 'escritura', 'dispositivos', FALSE),
('generacion_reportes', 'Generar reportes del sistema', 'lectura', 'reportes', FALSE),
('exportacion_datos', 'Exportar datos del sistema', 'lectura', 'reportes', TRUE),
('lectura_auditoria', 'Ver logs de auditoría', 'lectura', 'auditoria', TRUE),
('gestion_notificaciones', 'Gestionar notificaciones del sistema', 'administracion', 'notificaciones', FALSE),
('gestion_respaldos', 'Gestionar respaldos del sistema', 'administracion', 'respaldos', TRUE),
('restauracion_datos', 'Restaurar datos desde respaldos', 'administracion', 'respaldos', TRUE);

-- 8.4 CUARTO: Asignar permisos a roles (AHORA SÍ EXISTEN LOS PERMISOS)
INSERT INTO rol_permisos (rol_id, permiso_id, concedido_por) VALUES
(1, 1, 1), (1, 2, 1), (1, 3, 1), (1, 4, 1), (1, 5, 1), (1, 6, 1), (1, 7, 1), (1, 8, 1), (1, 9, 1),
(1, 10, 1), (1, 11, 1), (1, 12, 1), (1, 13, 1), (1, 14, 1), (1, 15, 1), (1, 16, 1), (1, 17, 1),
(1, 18, 1), (1, 19, 1), (1, 20, 1),
(2, 5, 1), (2, 6, 1), (2, 7, 1), (2, 8, 1), (2, 9, 1), (2, 10, 1), (2, 11, 1), (2, 12, 1),
(2, 15, 1), (2, 16, 1), (2, 17, 1), (2, 20, 1),
(3, 5, 1), (3, 6, 1), (3, 7, 1), (3, 8, 1), (3, 9, 1), (3, 10, 1), (3, 11, 1),
(3, 15, 1), (3, 17, 1),
(4, 5, 1), (4, 7, 1), (4, 8, 1), (4, 10, 1), (4, 11, 1), (4, 17, 1),
(5, 7, 1), (5, 8, 1), (5, 9, 1), (5, 10, 1), (5, 11, 1), (5, 13, 1), (5, 14, 1), (5, 17, 1),
(6, 7, 1), (6, 8, 1), (6, 10, 1), (6, 11, 1), (6, 17, 1),
(7, 7, 1), (7, 10, 1), (7, 17, 1),
(8, 7, 1), (8, 10, 1), (8, 17, 1),
(9, 17, 1);

-- 8.5 QUINTO: Insertar más usuarios 
INSERT INTO usuarios (nombre, email, password_hash, telefono,genero, estado) VALUES
('Dr. Carlos Rodríguez', 'carlos.rodriguez@hospital.com', '$2b$10$ExampleHash12345678901234567892', '+1234567892','M',TRUE),
('Dra. María González', 'maria.gonzalez@hospital.com', '$2b$10$ExampleHash12345678901234567893', '+1234567893','F',TRUE),
('Dr. Roberto Silva', 'roberto.silva@hospital.com', '$2b$10$ExampleHash12345678901234567894', '+1234567894','M', TRUE),
('Enf. Ana Martínez', 'ana.martinez@hospital.com', '$2b$10$ExampleHash12345678901234567895', '+1234567895','F', TRUE),
('Enf. Luis Torres', 'luis.torres@hospital.com', '$2b$10$ExampleHash12345678901234567896', '+1234567896','M', TRUE),
('Paciente Juan Pérez', 'juan.perez@email.com', '$2b$10$ExampleHash12345678901234567898', '+1234567898','M', TRUE),
('Paciente Marta López', 'marta.lopez@email.com', '$2b$10$ExampleHash12345678901234567899', '+1234567899','F', TRUE);

-- 8.6 SEXTO: Asignar roles detallados a usuarios
INSERT INTO usuario_roles (usuario_id, rol_id, asignado_por, es_rol_principal) VALUES
(1, 1, 1, TRUE),  -- Admin Principal -> administrador_sistema (10)
(2, 1, 1, TRUE),  -- Admin Soporte -> administrador_sistema (10)
(3, 2, 1, TRUE),  -- Dr. Carlos -> director_medico (9)
(4, 3, 1, TRUE),  -- Dra. María -> medico_especialista (7)
(5, 4, 1, TRUE),  -- Dr. Roberto -> medico_general (6)
(6, 5, 1, TRUE),  -- Enf. Ana -> enfermero_jefe (5)
(7, 6, 1, TRUE),  -- Enf. Luis -> enfermero (4)
(8, 7, 1, TRUE),  -- Juan Pérez -> paciente_avanzado (3)
(9, 8, 1, TRUE);  -- Marta López -> paciente (2)

-- =============================================
-- 9. AGREGAR FOREIGN KEYS. Se usan para establecer realciones entre tablas, Conecta una columna de una tabla (tabla hija) 	con la clave primaria de otra tabla ( tabla padre), Evita que se inserten valores en la tabla
-- hija que no existen en la tabla padre
-- =============================================

-- COMENTARIO: Se incluye el CREATE TABLE IF NOT EXISTS para 
-- asegurar que la tabla 'roles_detalle' sea la base para las FKs, aunque ya está creada.
CREATE TABLE IF NOT EXISTS roles_detalle (
    rol_id INT PRIMARY KEY AUTO_INCREMENT,
    nombre_rol VARCHAR(50) NOT NULL UNIQUE,
    descripcion TEXT,
    nivel_permisos INT DEFAULT 1,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    creado_por INT,
    FOREIGN KEY (creado_por) REFERENCES usuarios(usuario_id)
);

-- FKs para la jerarquía y seguridad
ALTER TABLE roles_detalle 
ADD CONSTRAINT fk_roles_creado_por 
FOREIGN KEY (creado_por) REFERENCES usuarios(usuario_id);

ALTER TABLE rol_permisos 
ADD CONSTRAINT fk_rol_permisos_rol 
FOREIGN KEY (rol_id) REFERENCES roles_detalle(rol_id) ON DELETE CASCADE;

-- MODIFICACIÓN: Se activa la FK a la tabla 'permisos' para asegurar la integridad referencial.
ALTER TABLE rol_permisos 
ADD CONSTRAINT fk_rol_permisos_permiso 
FOREIGN KEY (permiso_id) REFERENCES permisos(permiso_id) ON DELETE CASCADE;


ALTER TABLE rol_permisos 
ADD CONSTRAINT fk_rol_permisos_concedido_por 
FOREIGN KEY (concedido_por) REFERENCES usuarios(usuario_id);

ALTER TABLE usuario_roles 
ADD CONSTRAINT fk_usuario_roles_usuario 
FOREIGN KEY (usuario_id) REFERENCES usuarios(usuario_id) ON DELETE CASCADE;

ALTER TABLE usuario_roles 
ADD CONSTRAINT fk_usuario_roles_rol 
FOREIGN KEY (rol_id) REFERENCES roles_detalle(rol_id) ON DELETE CASCADE;

ALTER TABLE usuario_roles 
ADD CONSTRAINT fk_usuario_roles_asignado_por 
FOREIGN KEY (asignado_por) REFERENCES usuarios(usuario_id);

-- FKs para las tablas médicas
ALTER TABLE signos_vitales 
ADD CONSTRAINT fk_signos_paciente 
FOREIGN KEY (paciente_id) REFERENCES usuarios(usuario_id) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE signos_vitales 
ADD CONSTRAINT fk_signos_validado_por 
FOREIGN KEY (validado_por) REFERENCES usuarios(usuario_id) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE historial_clinico 
ADD CONSTRAINT fk_historial_paciente 
FOREIGN KEY (paciente_id) REFERENCES usuarios(usuario_id) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE historial_clinico 
ADD CONSTRAINT fk_historial_profesional 
FOREIGN KEY (profesional_id) REFERENCES usuarios(usuario_id) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE alertas 
ADD CONSTRAINT fk_alertas_paciente 
FOREIGN KEY (paciente_id) REFERENCES usuarios(usuario_id) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE alertas 
ADD CONSTRAINT fk_alertas_resuelta_por 
FOREIGN KEY (resuelta_por) REFERENCES usuarios(usuario_id) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE umbrales_alertas 
ADD CONSTRAINT fk_umbrales_paciente 
FOREIGN KEY (paciente_id) REFERENCES usuarios(usuario_id) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE umbrales_alertas 
ADD CONSTRAINT fk_umbrales_configurado_por 
FOREIGN KEY (configurado_por) REFERENCES usuarios(usuario_id) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE auditoria 
ADD CONSTRAINT fk_auditoria_usuario 
FOREIGN KEY (usuario_id) REFERENCES usuarios(usuario_id) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE notificaciones 
ADD CONSTRAINT fk_notificaciones_usuario 
FOREIGN KEY (usuario_id) REFERENCES usuarios(usuario_id) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE dispositivos 
ADD CONSTRAINT fk_dispositivos_paciente 
FOREIGN KEY (paciente_id) REFERENCES usuarios(usuario_id) ON DELETE CASCADE ON UPDATE CASCADE;

-- FKs para las tablas de respaldo
ALTER TABLE respaldos_logicos 
ADD CONSTRAINT fk_resp_logicos_usuario 
FOREIGN KEY (usuario_id) REFERENCES usuarios(usuario_id);

ALTER TABLE respaldos_fisicos 
ADD CONSTRAINT fk_resp_fisicos_usuario 
FOREIGN KEY (usuario_id) REFERENCES usuarios(usuario_id);

-- =============================================
-- 10. PROCEDIMIENTOS ALMACENADOS SIN TRANSACCIONES
-- =============================================
-- Cuando SE define un bloque de código como un procedimiento, el cuerpo incluye varias sentencias SQL que terminan en ;. Si no se cambia el delimitador, MySQL podría interpretar que el procedimiento termina en el
-- primer ; lo que genera errores de sintaxis.

DELIMITER //

/*
 * sp_registrar_signos_sin_transaccion. Registra un nuevo signo vital y audita el evento. No requiere una transaccion estricta ya que son dos INSERT independientes.
 IN verificar si un valor especifico coincide con alguno de los valores en una lista o el resultado de una subconsulta.
 */
CREATE PROCEDURE sp_registrar_signos_sin_transaccion(
    IN p_paciente_id INT,
    IN p_glucosa DECIMAL(5,2),
    IN p_presion_sistolica INT,
    IN p_presion_diastolica INT,
    IN p_peso DECIMAL(5,2),
    IN p_frecuencia_cardiaca INT,
    IN p_oxigenacion DECIMAL(5,2),
    IN p_tipo_registro ENUM('automatico', 'manual'),
    IN p_observaciones TEXT,
    IN p_usuario_id INT
)
BEGIN
    -- 1. Insertar signos vitales
    INSERT INTO signos_vitales (
        paciente_id, glucosa, presion_sistolica, presion_diastolica,
        peso, frecuencia_cardiaca, oxigenacion, tipo_registro, observaciones
    ) VALUES (
        p_paciente_id, p_glucosa, p_presion_sistolica, p_presion_diastolica,
        p_peso, p_frecuencia_cardiaca, p_oxigenacion, p_tipo_registro, p_observaciones
    );
    
    -- 2. Registrar en auditoría (usa LAST_INSERT_ID() como registro_id)
    INSERT INTO auditoria (
        tabla_afectada, operacion, registro_id, usuario_id,
        datos_nuevos, nivel_severidad
    ) VALUES (
        'signos_vitales', 'INSERT', LAST_INSERT_ID(), p_usuario_id,
        JSON_OBJECT(
            'paciente_id', p_paciente_id,
            'glucosa', p_glucosa,
            'presion_sistolica', p_presion_sistolica,
            'presion_diastolica', p_presion_diastolica,
            'peso', p_peso,
            'frecuencia_cardiaca', p_frecuencia_cardiaca,
            'oxigenacion', p_oxigenacion
        ),
        'info'
    );
    
    SELECT 'Signos vitales registrados exitosamente' AS mensaje, LAST_INSERT_ID() AS signo_vital_id;
END //

/*
 * sp_actualizar_perfil_sin_transaccion.  Obtiene los datos anteriores( del perfil) realiza un UPDATE en la tabla de usuarios y registra el cambio en auditoria.
 */
CREATE PROCEDURE sp_actualizar_perfil_sin_transaccion(
    IN p_usuario_id INT,
    IN p_nombre VARCHAR(100),
    IN p_telefono VARCHAR(20),
    IN p_direccion TEXT,
    IN p_codigo_postal VARCHAR(10),
    IN p_usuario_actualizacion INT  /*Que usuario hizo la actualizacion*/
)
BEGIN
    -- 1. Obtener datos anteriores para auditoría (antes de la actualización)
    SET @datos_anteriores = (
        SELECT JSON_OBJECT(
            'nombre', nombre,
            'telefono', telefono,
            'direccion', direccion,
            'codigo_postal', codigo_postal
        )
        FROM usuarios 
        WHERE usuario_id = p_usuario_id
    );
    
    -- 2. Actualizar usuario
    UPDATE usuarios 
    SET 
        nombre = p_nombre,
        telefono = p_telefono,
        direccion = p_direccion,
        codigo_postal = p_codigo_postal,
        fecha_actualizacion = CURRENT_TIMESTAMP
    WHERE usuario_id = p_usuario_id;
    
    -- 3. Registrar en auditoría (p_usuario_actualizacion es el que hace el cambio)
    INSERT INTO auditoria (
        tabla_afectada, operacion, registro_id, usuario_id,
        datos_anteriores, datos_nuevos, nivel_severidad
    ) VALUES (
        'usuarios', 'UPDATE', p_usuario_id, p_usuario_actualizacion,
        @datos_anteriores, -- Datos antes
        JSON_OBJECT(    -- Datos después (usando los parámetros de entrada)
            'nombre', p_nombre,
            'telefono', p_telefono,
            'direccion', p_direccion,
            'codigo_postal', p_codigo_postal
        ),
        'info'
    );
    
    SELECT 'Perfil actualizado exitosamente' AS mensaje;
END //

-- =============================================
-- 11. PROCEDIMIENTOS ALMACENADOS CON TRANSACCIONES
-- =============================================

/*
 * sp_registrar_historial_con_transaccion. Inserta una entrada en el historial_clinico y, si es urgente, genera una notificacion y registra la acción en auditoria. Todo debe completarse o anularse.
 TRANSACCION : Sí (START TRANSACTION, COMMIT, ROLLBACK en caso de error).
 */
CREATE PROCEDURE sp_registrar_historial_con_transaccion(
    IN p_paciente_id INT,
    IN p_tipo_entrada ENUM('diagnostico', 'medicamento', 'antecedente', 'laboratorio', 'evolucion'),
    IN p_titulo VARCHAR(200),
    IN p_descripcion TEXT,
    IN p_archivo_url VARCHAR(500),
    IN p_profesional_id INT,
    IN p_es_urgente BOOLEAN,
    IN p_categoria VARCHAR(100),
    IN p_nivel_confidencialidad ENUM('bajo', 'medio', 'alto', 'critico')
)
BEGIN
    -- Manejador de errores para forzar ROLLBACK
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    -- Manejador de errores o advertencias 
    BEGIN
        ROLLBACK;
        -- Deshacer las operaciones de modificacion de datos si no se ejecutaron correctamente.
        RESIGNAL;
        -- Volver a levantar la condicion que originalmente activo el manejador
    END;
    
    START TRANSACTION;
    
    -- 1. Insertar en historial clínico
    INSERT INTO historial_clinico (
        paciente_id, tipo_entrada, titulo, descripcion, archivo_url,
        profesional_id, es_urgente, categoria, nivel_confidencialidad
    ) VALUES (
        p_paciente_id, p_tipo_entrada, p_titulo, p_descripcion, p_archivo_url,
        p_profesional_id, p_es_urgente, p_categoria, p_nivel_confidencialidad
    );
    
    SET @historial_id = LAST_INSERT_ID();
    
    -- 2. Registrar en auditoría
    INSERT INTO auditoria (
        tabla_afectada, operacion, registro_id, usuario_id,
        datos_nuevos, nivel_severidad
    ) VALUES (
        'historial_clinico', 'INSERT', @historial_id, p_profesional_id,
        JSON_OBJECT(
            'paciente_id', p_paciente_id,
            'tipo_entrada', p_tipo_entrada,
            'titulo', p_titulo,
            'descripcion', LEFT(p_descripcion, 100),
            'es_urgente', p_es_urgente,
            'nivel_confidencialidad', p_nivel_confidencialidad
        ),
        'info'
    );
    
    -- 3. Crear notificación si es urgente
    IF p_es_urgente = TRUE THEN
        INSERT INTO notificaciones (
            usuario_id, titulo, mensaje, tipo, prioridad, url_destino
        ) VALUES (
            p_paciente_id, 
            'Nueva entrada urgente en historial',
            CONCAT('Se ha registrado una entrada urgente en su historial: ', p_titulo),
            'alerta', 
            'urgente',
            CONCAT('/historial/', @historial_id)
            -- Unir cadenas de texto
        );
    END IF;
    
    COMMIT;
    -- confirmar de forma permanente todos los cambios realizados en la transaccion actual
    SELECT 'Historial clínico registrado exitosamente' AS mensaje, @historial_id AS historial_id;
    -- no modifica la información; solo la lee y la devuelve como un conjunto de resultados
END //

/*
 * sp_transferir_paciente_con_transaccion. Simula la transferencia de un paciente a un nuevo médico, registrando el evento como una 'evolución' en el historial y notificando a ambos médicos.
 Sí (Incluye validaciones y SIGNAL de errores que fuerzan el ROLLBACK).
 */
CREATE PROCEDURE sp_transferir_paciente_con_transaccion(
    IN p_paciente_id INT,
    IN p_medico_anterior_id INT,
    IN p_medico_nuevo_id INT,
    IN p_usuario_administrador INT,
    IN p_razon_transferencia TEXT
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;
    
    START TRANSACTION;
    
    -- 1. Verificaciones de existencia (Si falla, el EXIT HANDLER ejecuta ROLLBACK).
    -- La verificación usa el rol detallado asignado como rol principal.
    
    -- Verificar si es un rol de paciente principal
    IF NOT EXISTS (SELECT 1 FROM usuario_roles ur JOIN roles_detalle rd ON ur.rol_id = rd.rol_id
    -- se utiliza para combinar filas de dos o más tablas basándose en una columna relacionada entre ellas, típicamente una clave foránea y su correspondiente clave primaria.
                   WHERE ur.usuario_id = p_paciente_id AND rd.nombre_rol LIKE 'paciente%' AND ur.es_rol_principal = TRUE) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'El paciente especificado no existe o no tiene un rol de paciente principal asignado.';
        -- generar un error personalizado de forma intencional. 
        -- Rango '45000': Es el código SQLSTATE genérico para los errores que no tienen un código predefinido por el estándar SQL. Esto asegura que no se colisionara con los códigos de error internos de MySQL.
    END IF;
    
    -- Verificar si el médico anterior tiene un rol médico principal
    IF NOT EXISTS (SELECT 1 FROM usuario_roles ur JOIN roles_detalle rd ON ur.rol_id = rd.rol_id
                   WHERE ur.usuario_id = p_medico_anterior_id AND rd.nombre_rol LIKE 'medico%' AND ur.es_rol_principal = TRUE) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'El médico anterior no existe o no tiene un rol médico principal asignado.';
    END IF;
    
    -- Verificar si el médico nuevo tiene un rol médico principal
    IF NOT EXISTS (SELECT 1 FROM usuario_roles ur JOIN roles_detalle rd ON ur.rol_id = rd.rol_id
                   WHERE ur.usuario_id = p_medico_nuevo_id AND rd.nombre_rol LIKE 'medico%' AND ur.es_rol_principal = TRUE) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'El médico nuevo no existe o no tiene un rol médico principal asignado.';
    END IF;
    
    -- 2. Registrar la transferencia en el historial clínico (como EVOLUCIÓN)
    INSERT INTO historial_clinico (
        paciente_id, tipo_entrada, titulo, descripcion,
        profesional_id, es_urgente, nivel_confidencialidad
    ) VALUES (
        p_paciente_id, 'evolucion',
        'Transferencia de médico tratante',
        CONCAT(
            'Transferencia del Dr. ', 
            (SELECT nombre FROM usuarios WHERE usuario_id = p_medico_anterior_id),
            ' al Dr. ',
            (SELECT nombre FROM usuarios WHERE usuario_id = p_medico_nuevo_id),
            '. Razón: ', p_razon_transferencia
        ),
        p_usuario_administrador, FALSE, 'medio'
    );
    
    SET @historial_id = LAST_INSERT_ID();
    -- Asignar valores a variables
    -- 3. Registrar en auditoría
    INSERT INTO auditoria (
        tabla_afectada, operacion, registro_id, usuario_id,
        datos_nuevos, nivel_severidad
    ) VALUES (
        'historial_clinico', 'INSERT', @historial_id, p_usuario_administrador,
        JSON_OBJECT(
            'paciente_id', p_paciente_id,
            'transferencia', 'true',
            'medico_anterior', p_medico_anterior_id,
            'medico_nuevo', p_medico_nuevo_id,
            'razon', p_razon_transferencia
        ),
        'advertencia'
    );
    
    -- 4. Crear notificaciones para ambos médicos
    INSERT INTO notificaciones (usuario_id, titulo, mensaje, tipo, prioridad) VALUES
    (
        p_medico_anterior_id,
        'Paciente transferido',
        CONCAT('El paciente ', (SELECT nombre FROM usuarios WHERE usuario_id = p_paciente_id), ' ha sido transferido a otro médico.'),
        'sistema',
        'media'
    ),
    (
        p_medico_nuevo_id,
        'Nuevo paciente asignado',
        CONCAT('Se le ha asignado el paciente ', (SELECT nombre FROM usuarios WHERE usuario_id = p_paciente_id), '.'),
        'sistema',
        'alta'
    );
    
    COMMIT;
    
    SELECT 'Paciente transferido exitosamente' AS mensaje;
END //

-- =============================================
-- 12. PROCEDIMIENTOS PARA RESPALDO LÓGICO (SIMULACIÓN DE EXPORTACIÓN DE DATOS)
-- =============================================

/*
 * sp_generar_respaldo_logico. Simular la generación y el registro de un respaldo lógico. es fundamental para el Módulo de Logística y Auditoría de la base de datos, ya que no ejecuta una copia de seguridad 
 física real del motor de MySQL, sino que documenta y audita el proceso de creación de un archivo de backup de datos esenciales. p_usuario_id --> indica quien esta realizando la operacion
 */
CREATE PROCEDURE sp_generar_respaldo_logico(IN p_usuario_id INT)
BEGIN
    DECLARE v_fecha_respaldo VARCHAR(20);
    DECLARE v_tablas_respaldadas INT DEFAULT 0;
    DECLARE v_total_registros INT DEFAULT 0;
    
    SET v_fecha_respaldo = DATE_FORMAT(NOW(), '%Y%m%d_%H%i%s');
    
    -- 1. Asegurar la limpieza y creación de la tabla temporal.
    DROP TEMPORARY TABLE IF EXISTS respaldo_logico_temp;
    
    -- Crear tabla temporal para el respaldo. Se crea una tabla temporal llamada respaldo_logico_temp para simular el archivo de respaldo exportado.
    CREATE TEMPORARY TABLE respaldo_logico_temp (
        tabla_nombre VARCHAR(50),
        datos_json JSON,
        fecha_respaldo DATETIME,
        registros_backup INT
    );
    
    -- 2. Respaldar datos (usando JSON_ARRAYAGG para simular el contenido del archivo). Utiliza la función JSON_ARRAYAGG para convertir los registros de cada tabla en un objeto JSON que representa el contenido del dump 
    -- o archivo de respaldo, simulando la exportación de los datos.
    INSERT INTO respaldo_logico_temp (tabla_nombre, datos_json, fecha_respaldo, registros_backup)
    SELECT 'usuarios', JSON_ARRAYAGG(JSON_OBJECT(
        'usuario_id', usuario_id,
        'nombre', nombre,
        'email', email,
        'estado', estado,
        'fecha_creacion', fecha_creacion
    )), NOW(), COUNT(*)
    FROM usuarios;
    
    -- Respaldar roles y permisos
    INSERT INTO respaldo_logico_temp (tabla_nombre, datos_json, fecha_respaldo, registros_backup)
    SELECT 'roles_detalle', JSON_ARRAYAGG(JSON_OBJECT(
        'rol_id', rol_id,
        'nombre_rol', nombre_rol,
        'descripcion', descripcion,
        'nivel_permisos', nivel_permisos
    )), NOW(), COUNT(*)
    FROM roles_detalle;
    
    -- Respaldar asignaciones de roles (si existen registros)
    INSERT INTO respaldo_logico_temp (tabla_nombre, datos_json, fecha_respaldo, registros_backup)
    SELECT 'usuario_roles', 
           COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
            'usuario_rol_id', usuario_rol_id,
            'usuario_id', usuario_id,
            'rol_id', rol_id,
            'es_rol_principal', es_rol_principal
        )), JSON_ARRAY()), 
        NOW(), 
        COUNT(*)
    FROM usuario_roles;
    
    -- 3. Calcular totales para el log de auditoría. Calcula el número de tablas respaldadas y el total de registros exportados al sumar los registros de las tablas cargadas en la tabla temporal.
    SELECT COUNT(*), COALESCE(SUM(registros_backup), 0)
    INTO v_tablas_respaldadas, v_total_registros
    FROM respaldo_logico_temp;
    
    -- 4. Registrar el evento en auditoría. Registra la operación en la tabla auditoria con los siguientes detalles: tabla_afectada: 'sistema'. operacion: 'BACKUP'.datos_nuevos: Un objeto JSON que contiene el tipo de 
    -- respaldo (respaldo_logico), la fecha_respaldo (con formato timestamp), el número de tablas_respaldadas y el total_registros. usuario_id: El ID del usuario que ejecutó el procedimiento.
    INSERT INTO auditoria (
        tabla_afectada, operacion, registro_id, usuario_id,
        datos_nuevos, nivel_severidad
    ) VALUES (
        'sistema', 'BACKUP', 0, p_usuario_id,
        JSON_OBJECT(
            'tipo', 'respaldo_logico',
            'fecha_respaldo', v_fecha_respaldo,
            'tablas_respaldadas', v_tablas_respaldadas,
            'total_registros', v_total_registros
        ),
        'info'
    );
    
    -- 5. Devolver resumen del respaldo y limpiar temporal
    SELECT 
        'Respaldo lógico generado exitosamente' AS mensaje,
        v_fecha_respaldo AS fecha_respaldo,
        v_tablas_respaldadas AS tablas_respaldadas,
        v_total_registros AS total_registros;
    
    DROP TEMPORARY TABLE respaldo_logico_temp;
    -- Devuelve un mensaje de éxito con un resumen del respaldo (tablas y registros totales). Elimina la tabla temporal (respaldo_logico_temp) una vez finalizado el proceso.

END //

/*
 * sp_respaldo_logico_completo.  Registra el inicio, simula y marca el respaldo como 'completado' en respaldos_logicos, y audita el proceso. Sí (Maneja fallos marcando el registro como 'fallido').
 */
CREATE PROCEDURE sp_respaldo_logico_completo(IN p_usuario_id INT)
BEGIN
    DECLARE v_respaldo_id INT;
    DECLARE v_fecha_respaldo VARCHAR(20);
    DECLARE v_total_registros INT DEFAULT 0;
    
    SET v_fecha_respaldo = DATE_FORMAT(NOW(), '%Y%m%d_%H%i%s');
    
    START TRANSACTION;
    
    BEGIN
        DECLARE EXIT HANDLER FOR SQLEXCEPTION
        BEGIN
            -- Si falla, marca el respaldo como 'fallido' y realiza ROLLBACK
            ROLLBACK;
            UPDATE respaldos_logicos SET estado = 'fallido' WHERE respaldo_id = v_respaldo_id;
            RESIGNAL;
        END;
        
        -- 1. Registrar inicio del respaldo
        INSERT INTO respaldos_logicos (usuario_id, tipo_respaldo, estado)
        VALUES (p_usuario_id, 'completo', 'en_proceso');
        
        SET v_respaldo_id = LAST_INSERT_ID();
        
        -- 2. Simular proceso de respaldo (pausa)
        DO SLEEP(1);
        
        -- 3. Calcular total de registros (simulado)
        SET v_total_registros = (
            SELECT COUNT(*) FROM usuarios
        ) + (
            SELECT COUNT(*) FROM roles_detalle
        ) + (
            SELECT COUNT(*) FROM permisos
        ) + (
            SELECT COUNT(*) FROM usuario_roles
        ) + (
            SELECT COUNT(*) FROM rol_permisos
        ) + (
            SELECT COUNT(*) FROM historial_clinico
        ) + (
            SELECT COUNT(*) FROM signos_vitales
        ) + (
            SELECT COUNT(*) FROM alertas
        );
        
        -- 4. Actualizar registro con información final
        UPDATE respaldos_logicos 
        SET 
            tablas_incluidas = 'usuarios,roles_detalle,permisos,usuario_roles,rol_permisos,historial_clinico,signos_vitales,alertas',
            total_registros = v_total_registros,
            tamaño_estimado_mb = ROUND(v_total_registros * 0.1, 2),
            ruta_archivo = CONCAT('/backups/healthguard_completo_', v_fecha_respaldo, '.sql'),
            estado = 'completado'
        WHERE respaldo_id = v_respaldo_id;
        
        -- 5. Registrar en auditoría
        INSERT INTO auditoria (
            tabla_afectada, operacion, registro_id, usuario_id,
            datos_nuevos, nivel_severidad
        ) VALUES (
            'sistema', 'BACKUP', v_respaldo_id, p_usuario_id,
            JSON_OBJECT(
                'tipo', 'respaldo_logico_completo',
                'fecha_respaldo', v_fecha_respaldo,
                'respaldo_id', v_respaldo_id,
                'total_registros', v_total_registros
            ),
            'info'
        );
        
        COMMIT;
        
        SELECT 
            'Respaldo lógico completo generado exitosamente' AS mensaje,
            v_respaldo_id AS respaldo_id,
            v_fecha_respaldo AS fecha_respaldo,
            ruta_archivo,
            total_registros,
            tamaño_estimado_mb
        FROM respaldos_logicos 
        WHERE respaldo_id = v_respaldo_id;
    END;
END //

-- =============================================
-- 13. PROCEDIMIENTOS PARA RESTAURACIÓN LÓGICA 
-- =============================================

/*
 * sp_restaurar_respaldo_logico. Simular y auditar el proceso de restauración de datos en el sistema HealthGuard Pro a partir de un respaldo lógico previamente generado.
 El procedimiento acepta dos parámetros: el ID del respaldo a restaurar (p_respaldo_id) y el ID del usuario que solicita la restauración (p_usuario_id).
 Sirve como el mecanismo de seguridad y auditoría para revertir la base de datos a un estado anterior usando un archivo de respaldo lógico, garantizando que solo personal autorizado pueda ejecutar esta acción crítica.
 */
CREATE PROCEDURE sp_restaurar_respaldo_logico(
    IN p_respaldo_id INT,
    IN p_usuario_id INT
)
BEGIN
    DECLARE v_tablas_restauradas INT DEFAULT 0;
    DECLARE v_total_registros INT DEFAULT 0;

    -- 1. Verificar permisos de administrador (Nivel de Permisos >= 9)
    IF NOT EXISTS (
        SELECT 1 FROM usuario_roles ur
        JOIN roles_detalle rd ON ur.rol_id = rd.rol_id
        WHERE ur.usuario_id = p_usuario_id 
        AND rd.nivel_permisos >= 9 -- Solo Director Médico o Admin
        AND ur.es_rol_principal = TRUE
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Permisos insuficientes para realizar restauración';
    END IF;

    -- 2. Verificar que el respaldo existe y está 'completado'
    IF NOT EXISTS (
        SELECT 1 FROM respaldos_logicos 
        WHERE respaldo_id = p_respaldo_id AND estado = 'completado'
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Respaldo no encontrado o no está disponible para restauración';
    END IF;

    START TRANSACTION;

    BEGIN
        DECLARE EXIT HANDLER FOR SQLEXCEPTION
        BEGIN
            -- Si falla, registra el error de restauración y actualiza el log
            ROLLBACK;

            INSERT INTO auditoria (
                tabla_afectada, operacion, registro_id, usuario_id,
                datos_nuevos, nivel_severidad
            ) VALUES (
                'respaldos_logicos', 'RESTORE', p_respaldo_id, p_usuario_id,
                JSON_OBJECT('estado', 'fallido', 'mensaje', 'Error durante restauración'),
                'error'
            );

            UPDATE respaldos_logicos 
            SET estado = 'fallido' 
            WHERE respaldo_id = p_respaldo_id;

            RESIGNAL;
        END;

        -- 3. Simular restauración
        SELECT SLEEP(2);

        SET v_tablas_restauradas = 8;
        SET v_total_registros = 150;

        -- 4. Registrar restauración exitosa en auditoría
        INSERT INTO auditoria (
            tabla_afectada, operacion, registro_id, usuario_id,
            datos_nuevos, nivel_severidad
        ) VALUES (
            'respaldos_logicos', 'RESTORE', p_respaldo_id, p_usuario_id,
            JSON_OBJECT(
                'estado', 'completado',
                'tablas_restauradas', v_tablas_restauradas,
                'total_registros', v_total_registros
            ),
            'info'
        );

        COMMIT;

        SELECT 
            'Restauración lógica completada exitosamente' AS mensaje,
            v_tablas_restauradas AS tablas_restauradas,
            v_total_registros AS registros_restaurados,
            p_respaldo_id AS respaldo_utilizado;
    END;
END //

-- =============================================
-- 14. PROCEDIMIENTOS PARA RESPALDO FÍSICO (SIMULACIÓN)
-- =============================================

/*
 * sp_simular_respaldo_fisico. Simular y auditar la ejecución de un respaldo físico completo de la base de datos healthguard_pro a nivel de sistema de archivos o motor de base de datos. 
   Este tipo de respaldo es más crítico que el lógico, ya que implica la copia de toda la estructura y datos del motor. Registra el evento de respaldo físico, lo audita y asegura la integridad de la información del log.
 */
CREATE PROCEDURE sp_simular_respaldo_fisico(IN p_usuario_id INT)
BEGIN
    DECLARE v_respaldo_id INT;
    DECLARE v_fecha_respaldo VARCHAR(20);
    DECLARE v_inicio TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    DECLARE v_duracion INT;
    
    SET v_fecha_respaldo = DATE_FORMAT(NOW(), '%Y%m%d_%H%i%s');
    
    START TRANSACTION;
    
    BEGIN
        DECLARE EXIT HANDLER FOR SQLEXCEPTION
        BEGIN
            ROLLBACK;
            UPDATE respaldos_fisicos SET estado = 'fallido' WHERE respaldo_id = v_respaldo_id;
            RESIGNAL;
        END;
        
        -- 1. Registrar inicio
        INSERT INTO respaldos_fisicos (
            usuario_id, tipo_respaldo, base_datos, estado
        ) VALUES (
            p_usuario_id, 'completo', 'healthguard_pro', 'en_proceso'
        );
        
        SET v_respaldo_id = LAST_INSERT_ID();
        
        -- 2. Simular proceso
        DO SLEEP(2);
        
        SET v_duracion = TIMESTAMPDIFF(SECOND, v_inicio, CURRENT_TIMESTAMP);
        
        -- 3. Actualizar con datos finales
        UPDATE respaldos_fisicos 
        SET 
            tamaño_mb = 245.75,
            ruta_archivo = CONCAT('/physical_backups/healthguard_complete_', v_fecha_respaldo, '.bak'),
            checksum = SHA2(CONCAT('healthguard_pro', v_fecha_respaldo), 256),
            estado = 'completado',
            duracion_segundos = v_duracion
        WHERE respaldo_id = v_respaldo_id;
        
        -- 4. Registrar en auditoría
        INSERT INTO auditoria (
            tabla_afectada, operacion, registro_id, usuario_id,
            datos_nuevos, nivel_severidad
        ) VALUES (
            'sistema', 'BACKUP', v_respaldo_id, p_usuario_id,
            JSON_OBJECT(
                'tipo', 'respaldo_fisico',
                'fecha_respaldo', v_fecha_respaldo,
                'base_datos', 'healthguard_pro',
                'tamaño_mb', 245.75,
                'duracion_segundos', v_duracion
            ),
            'info'
        );
        
        COMMIT;
        
        SELECT 
            'Respaldo físico simulado exitosamente' AS mensaje,
            v_respaldo_id AS respaldo_id,
            fecha_respaldo,
            tamaño_mb,
            ruta_archivo,
            checksum,
            duracion_segundos
        FROM respaldos_fisicos 
        WHERE respaldo_id = v_respaldo_id;
    END;
END //

-- =============================================
-- 15. PROCEDIMIENTOS PARA RESTAURACIÓN FÍSICA (SIMULACIÓN)
-- =============================================

/*
 * sp_simular_restauracion_fisica. Simular y auditar el proceso de restauración total y crítica de la base de datos healthguard_pro a partir de un respaldo físico previamente generado.
Este procedimiento es el más restrictivo y de mayor nivel de seguridad, ya que una restauración física implica la posible sobrescritura de toda la base de datos.
 */
CREATE PROCEDURE sp_simular_restauracion_fisica(
    IN p_respaldo_id INT,
    IN p_usuario_id INT
)
BEGIN
    DECLARE v_ruta_archivo VARCHAR(500);
    DECLARE v_base_datos VARCHAR(100);
    DECLARE v_checksum VARCHAR(64);
    DECLARE v_inicio TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    DECLARE v_duracion INT;

    -- 1. Verificar permisos de administrador (Nivel de Permisos = 10)
    IF NOT EXISTS (
        SELECT 1 FROM usuario_roles ur
        JOIN roles_detalle rd ON ur.rol_id = rd.rol_id
        WHERE ur.usuario_id = p_usuario_id 
        AND rd.nivel_permisos = 10 -- Solo Administrador de Sistema
        AND ur.es_rol_principal = TRUE
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Se requieren permisos de administrador del sistema para restauración física';
    END IF;

    -- 2. Obtener información del respaldo. Obtiene la información clave del respaldo (ruta, base de datos, checksum) y verifica que el respaldo_id especificado exista en la tabla respaldos_fisicos y que su estado sea 'completado'.
    SELECT ruta_archivo, base_datos, checksum
    INTO v_ruta_archivo, v_base_datos, v_checksum
    FROM respaldos_fisicos
    WHERE respaldo_id = p_respaldo_id AND estado = 'completado';

    IF v_ruta_archivo IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Respaldo físico no encontrado o no completado';
    END IF;

    START TRANSACTION;

    BEGIN
        DECLARE EXIT HANDLER FOR SQLEXCEPTION
        BEGIN
            -- Si falla, registra el error
            ROLLBACK;

            INSERT INTO auditoria (
                tabla_afectada, operacion, registro_id, usuario_id,
                datos_nuevos, nivel_severidad
            ) VALUES (
                'respaldos_fisicos', 'RESTORE', p_respaldo_id, p_usuario_id,
                JSON_OBJECT('estado', 'fallido', 'mensaje', 'Error durante restauración física'),
                'error'
            );

            UPDATE respaldos_fisicos 
            SET estado = 'fallido' 
            WHERE respaldo_id = p_respaldo_id;

            RESIGNAL;
        END;

        -- 3. Simular proceso. Una vez "completada" la restauración, se registra en la tabla auditoria con la operación 'RESTORE' y un nivel de severidad 'info'.
        SELECT SLEEP(3);

        SET v_duracion = TIMESTAMPDIFF(SECOND, v_inicio, CURRENT_TIMESTAMP);

        -- 4. Actualizar estado del respaldo a 'completado' (restaurado)
        UPDATE respaldos_fisicos 
        SET estado = 'completado' 
        WHERE respaldo_id = p_respaldo_id;

        -- 5. Registrar restauración exitosa en auditoría
        INSERT INTO auditoria (
            tabla_afectada, operacion, registro_id, usuario_id,
            datos_nuevos, nivel_severidad
        ) VALUES (
            'respaldos_fisicos', 'RESTORE', p_respaldo_id, p_usuario_id,
            JSON_OBJECT(
                'estado', 'completado',
                'tipo', 'fisico',
                'base_datos', v_base_datos,
                'respaldo_utilizado', p_respaldo_id,
                'ruta_archivo', v_ruta_archivo,
                'checksum_verificado', TRUE,
                'duracion_segundos', v_duracion
            ),
            'info'
        );

        -- 6. Simular reinicio de sesiones (práctica de seguridad tras restauración crítica)
        UPDATE usuarios 
        SET ultimo_login = NULL, 
            intentos_login = 0,
            cuenta_bloqueada = FALSE
        WHERE estado = TRUE;

        COMMIT;

        SELECT 
            'Restauración física simulada exitosamente' AS mensaje,
            p_respaldo_id AS respaldo_utilizado,
            v_base_datos AS base_datos_restaurada,
            v_ruta_archivo AS archivo_respaldo,
            v_duracion AS duracion_segundos,
            'Todos los usuarios han sido desconectados. Requiere nuevo login.' AS nota_importante;
    END;
END //

DELIMITER ;

-- =============================================
-- 16. CONFIGURACIÓN DE SEGURIDAD A NIVEL DE MYSQL 8.0+. Control de acceso basado en roles (RBCA)
-- =============================================

-- 16.1 ELIMINACIÓN PREVIA DE ROLES Y USUARIOS. Que se pueda ejecutar varias veces sin causar errores ni duplicar configuraciones 
DROP ROLE IF EXISTS 
    'administrador_sistema_role', 
    'director_medico_role',
    'medico_especialista_role',
    'medico_general_role',
    'enfermero_jefe_role',
    'enfermero_role',
    'paciente_avanzado_role',
    'paciente_role',
    'invitado_role';

DROP USER IF EXISTS 
    'sysadmin'@'localhost', 
    'juan_perez_avz_db'@'localhost';
    
-- 16.2 CREACIÓN DE LOS 9 ROLES DE MYSQL
CREATE ROLE 
    'administrador_sistema_role', 
    'director_medico_role',
    'medico_especialista_role', 
    'medico_general_role',
    'enfermero_jefe_role',      
    'enfermero_role',
    'paciente_avanzado_role',   
    'paciente_role',
    'invitado_role';            

-- =============================================
-- 16.3 ASIGNACIÓN DE PRIVILEGIOS A LOS 9 ROLES. Se otorgan privilegios físicos (SELECT, INSERT, UPDATE, DELETE, EXECUTE) a cada uno de los roles, limitando su acceso a tablas y procedimientos almacenados específicos:
-- administrador_sistema_role: Recibe ALL (todos) los privilegios en la base de datos healthguard_pro.
-- medico_especialista_role: Recibe SELECT, INSERT, UPDATE, DELETE en tablas médicas (historial_clinico, signos_vitales) y permisos EXECUTE en procedimientos como sp_registrar_historial_con_transaccion.
-- paciente_avanzado_role: Solo tiene SELECT, INSERT en sus datos (historial_clinico, signos_vitales) y permiso para ejecutar el procedimiento de actualización de perfil (sp_actualizar_perfil_sin_transaccion).
-- =============================================

-- A. Rol Administrador de Sistema (Nivel 10)
GRANT ALL ON healthguard_pro.* TO 'administrador_sistema_role';
GRANT EXECUTE ON healthguard_pro.* TO 'administrador_sistema_role';

-- B. Rol Director Médico (Nivel 9)
GRANT SELECT, INSERT, UPDATE, DELETE ON healthguard_pro.* TO 'director_medico_role';
GRANT EXECUTE ON healthguard_pro.* TO 'director_medico_role';

-- C. Rol Médico Especialista (Nivel 7: Acceso completo a pacientes asignados)
GRANT SELECT, INSERT, UPDATE, DELETE ON healthguard_pro.historial_clinico TO 'medico_especialista_role';
GRANT SELECT, INSERT, UPDATE, DELETE ON healthguard_pro.signos_vitales TO 'medico_especialista_role';
GRANT SELECT ON healthguard_pro.usuarios TO 'medico_especialista_role';
GRANT EXECUTE ON PROCEDURE healthguard_pro.sp_registrar_historial_con_transaccion TO 'medico_especialista_role';
GRANT EXECUTE ON PROCEDURE healthguard_pro.sp_registrar_signos_sin_transaccion TO 'medico_especialista_role';

-- D. Rol Médico General (Nivel 6: Acceso básico a funcionalidades médicas)
GRANT SELECT, INSERT, UPDATE ON healthguard_pro.historial_clinico TO 'medico_general_role';
GRANT SELECT, INSERT, UPDATE ON healthguard_pro.signos_vitales TO 'medico_general_role';
GRANT SELECT ON healthguard_pro.usuarios TO 'medico_general_role';
GRANT EXECUTE ON PROCEDURE healthguard_pro.sp_registrar_historial_con_transaccion TO 'medico_general_role';
GRANT EXECUTE ON PROCEDURE healthguard_pro.sp_registrar_signos_sin_transaccion TO 'medico_general_role';

-- E. Rol Enfermero Jefe (Nivel 5: Supervisión y permisos extendidos)
GRANT SELECT, INSERT, UPDATE, DELETE ON healthguard_pro.signos_vitales TO 'enfermero_jefe_role';
GRANT SELECT, INSERT, UPDATE ON healthguard_pro.dispositivos TO 'enfermero_jefe_role';
GRANT SELECT ON healthguard_pro.alertas TO 'enfermero_jefe_role';
GRANT SELECT ON healthguard_pro.umbrales_alertas TO 'enfermero_jefe_role'; 
GRANT EXECUTE ON PROCEDURE healthguard_pro.sp_registrar_signos_sin_transaccion TO 'enfermero_jefe_role';

-- F. Rol Enfermero (Nivel 4: Registro y monitoreo de signos vitales)
GRANT SELECT, INSERT ON healthguard_pro.signos_vitales TO 'enfermero_role';
GRANT UPDATE ON healthguard_pro.signos_vitales TO 'enfermero_role'; 
GRANT SELECT ON healthguard_pro.dispositivos TO 'enfermero_role';
GRANT EXECUTE ON PROCEDURE healthguard_pro.sp_registrar_signos_sin_transaccion TO 'enfermero_role';

-- G. Rol Paciente Avanzado (Nivel 3: Acceso extendido a sus propios datos)
GRANT SELECT ON healthguard_pro.historial_clinico TO 'paciente_avanzado_role';
GRANT SELECT, INSERT ON healthguard_pro.signos_vitales TO 'paciente_avanzado_role';
GRANT EXECUTE ON PROCEDURE healthguard_pro.sp_actualizar_perfil_sin_transaccion TO 'paciente_avanzado_role';

-- H. Rol Paciente (Nivel 2: Acceso básico a su información)
GRANT SELECT ON healthguard_pro.historial_clinico TO 'paciente_role';
GRANT SELECT ON healthguard_pro.signos_vitales TO 'paciente_role';
GRANT EXECUTE ON PROCEDURE healthguard_pro.sp_actualizar_perfil_sin_transaccion TO 'paciente_role';

-- I. Rol Invitado (Nivel 1: Solo lectura de información pública)
GRANT SELECT ON healthguard_pro.usuarios TO 'invitado_role';

--
-- 16.4 CREACIÓN DE USUARIOS DE MYSQL (LOGINS). Se crean las cuentas de login para el motor MySQL
CREATE USER 'sysadmin'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'AdminPasswordStrong123!';
CREATE USER 'juan_perez_avz_db'@'localhost' IDENTIFIED WITH caching_sha2_password BY 'PacienteAvzPass456';

-- 16.5 ASIGNACIÓN DE ROLES DE MYSQL A USUARIOS Y ACTIVACIÓN

-- Asignar el rol al administrador del sistema
GRANT 'administrador_sistema_role' TO 'sysadmin'@'localhost';

-- Asignar el rol al paciente avanzado (ejemplo)
GRANT 'paciente_avanzado_role' TO 'juan_perez_avz_db'@'localhost';

-- Establecer el rol como predeterminado (activado automáticamente al iniciar sesión). El usuario obtendrá automáticamente esos privilegios al conectarse al servidor.
SET DEFAULT ROLE ALL TO 'sysadmin'@'localhost', 'juan_perez_avz_db'@'localhost';

-- 16.6 APLICAR CAMBIOS Y VERIFICACIÓN
FLUSH PRIVILEGES;

SELECT 'Los 9 Roles y usuarios de MySQL 8.0+ se han creado y configurado exitosamente.' as Estado;

-- =============================================
-- 17. VISTAS EXISTENTES DEL SISTEMA (SEGURIDAD Y PERMISOS). Las vistas son tablas virtuales que simplifican consultas complejas y facilitan el análisis de grandes volúmenes de datos, especialmente en temas de seguridad y auditoría.
--  
-- =============================================

-- Vista: Resumen de permisos por rol. Todos los permisos asignados a cada rol detallado del sistema.
CREATE OR REPLACE VIEW vista_permisos_por_rol AS
SELECT 
    rd.nombre_rol,
    rd.descripcion as descripcion_rol,
    rd.nivel_permisos,
    p.nombre_permiso,
    p.descripcion as descripcion_permiso,
    p.categoria,
    p.modulo,
    p.es_critico,
    u.nombre as concedido_por,
    rp.fecha_concesion
FROM roles_detalle rd
JOIN rol_permisos rp ON rd.rol_id = rp.rol_id
JOIN permisos p ON rp.permiso_id = p.permiso_id
JOIN usuarios u ON rp.concedido_por = u.usuario_id
WHERE (rp.fecha_expiracion IS NULL OR rp.fecha_expiracion > NOW())
ORDER BY rd.nivel_permisos DESC, p.modulo, p.categoria;

-- Vista: Usuarios con sus roles y permisos.Esta vista ofrece un resumen centralizado de cada usuario, sus roles asignados y una lista concatenada de todos sus permisos efectivos.
CREATE OR REPLACE VIEW vista_usuarios_permisos AS
SELECT 
    u.usuario_id,
    u.nombre as nombre_usuario,
    u.email,
    -- u.rol as rol_base, <-- ROL_BASE ELIMINADO
    u.estado as usuario_activo,
    rd.nombre_rol as rol_detallado,
    rd.nivel_permisos,
    -- Concatena todos los permisos del usuario en una sola cadena
    GROUP_CONCAT(DISTINCT p.nombre_permiso ORDER BY p.nombre_permiso SEPARATOR ', ') as permisos,
    ur.fecha_asignacion,
    ur.es_rol_principal
FROM usuarios u
JOIN usuario_roles ur ON u.usuario_id = ur.usuario_id
JOIN roles_detalle rd ON ur.rol_id = rd.rol_id
JOIN rol_permisos rp ON rd.rol_id = rp.rol_id
JOIN permisos p ON rp.permiso_id = p.permiso_id
WHERE u.estado = TRUE 
    AND (ur.fecha_expiracion IS NULL OR ur.fecha_expiracion > NOW())
    AND (rp.fecha_expiracion IS NULL OR rp.fecha_expiracion > NOW())
GROUP BY u.usuario_id, u.nombre, u.email, rd.nombre_rol, rd.nivel_permisos, ur.fecha_asignacion, ur.es_rol_principal
ORDER BY rd.nivel_permisos DESC, u.nombre;

-- =============================================
-- 18. CONSULTAS DE VERIFICACIÓN FINAL (DOCUMENTACIÓN)
-- =============================================

SELECT 'Base de datos HealthGuard Pro creada exitosamente!' as Mensaje;
SELECT 'Sistema de roles, permisos y respaldos configurado correctamente.' as Estado;
SELECT COUNT(*) as 'Total Usuarios' FROM usuarios;
SELECT COUNT(*) as 'Total Roles' FROM roles_detalle;
SELECT COUNT(*) as 'Total Permisos' FROM permisos;
SELECT COUNT(*) as 'Total Asignaciones Rol-Permiso' FROM rol_permisos;
SELECT COUNT(*) as 'Procedimientos Creados' FROM information_schema.ROUTINES 
WHERE ROUTINE_SCHEMA = DATABASE() AND ROUTINE_TYPE = 'PROCEDURE';

-- Mostrar procedimientos disponibles (para verificar la creación)
SELECT 
    ROUTINE_NAME as 'Procedimiento',
    ROUTINE_TYPE as 'Tipo'
FROM information_schema.ROUTINES 
WHERE ROUTINE_SCHEMA = DATABASE()
ORDER BY ROUTINE_NAME;

SELECT '=== SISTEMA HEALTHGUARD PRO COMPLETO Y DOCUMENTADO ===' as Finalizado;

-- =============================================
-- 19. EJEMPLOS DE USO DE LOS PROCEDIMIENTOS (PARA PRUEBAS)
-- =============================================

-- Ejemplo 1: Registrar signos vitales sin transacción
-- Parámetros: Paciente ID (8), Glucosa (120.5), Psistólica (120), Pdiastólica (80), Peso (70.5), FCardiaca (75), Oxigenación (98.5), Tipo ('manual'), Observaciones, Usuario que registra (3)
CALL sp_registrar_signos_sin_transaccion(8, 120.5, 120, 80, 70.5, 75, 98.5, 'manual', 'Registro rutinario', 3);

-- Ejemplo 2: Actualizar perfil de usuario (por Admin 1)
-- Parámetros: Usuario a actualizar (8), Nuevo Nombre, Teléfono, Dirección, CP, Usuario que actualiza (1)
CALL sp_actualizar_perfil_sin_transaccion(8, 'Juan Pérez Actualizado', '+1234567890', 'Nueva Dirección 123', '28001', 1);

-- Ejemplo 3: Registrar historial con transacción (Urgente por Médico 3)
-- Parámetros: Paciente (8), Tipo ('diagnostico'), Título, Descripción, Archivo (NULL), Profesional (3), Es Urgente (FALSE), Categoría, Nivel Confidencialidad
CALL sp_registrar_historial_con_transaccion(8, 'diagnostico', 'Control diabetes', 'Paciente con control estable de glucosa', NULL, 3, FALSE, 'Endocrinología', 'medio');

-- Ejemplo 4: Generar respaldo lógico (por Admin 1)
CALL sp_generar_respaldo_logico(1);

-- Ejemplo 5: Generar respaldo físico simulado (por Admin 1)
CALL sp_simular_respaldo_fisico(1);