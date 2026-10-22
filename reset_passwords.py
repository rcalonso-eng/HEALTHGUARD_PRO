# reset_passwords.py
from main import app
from models import db, Usuario

passwords = {
    "admin@hospital.com":             "admin123",
    "soporte@hospital.com":           "soporte123",
    "carlos.rodriguez@hospital.com":  "medico123",
    "maria.gonzalez@hospital.com":    "medico123",
    "roberto.silva@hospital.com":     "medico123",
    "ana.martinez@hospital.com":      "enfermero123",
    "luis.torres@hospital.com":       "enfermero123",
    "juan.perez@email.com":           "paciente123",
    "marta.lopez@email.com":          "paciente123",
}

with app.app_context():
    for email, pwd in passwords.items():
        u = Usuario.query.filter_by(email=email).first()
        if u:
            u.password = pwd          # el setter hashea con pbkdf2:sha256
            u.cuenta_bloqueada = False
            u.intentos_login = 0
            print(f"✔ Actualizado: {email}")
        else:
            print(f"✘ No encontrado: {email}")
    db.session.commit()
    print("\n✅ Contraseñas actualizadas correctamente.")