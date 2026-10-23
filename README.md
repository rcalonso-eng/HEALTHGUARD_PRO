# HealthGuard Pro

Sistema de monitoreo médico inteligente con gestión de roles (RBAC),
auditoría y respaldos.

## Stack
- Flask 2.3 + Flask-Login + Flask-Bootstrap
- SQLAlchemy ORM + MySQL 8 (PyMySQL)
- Jinja2 + Bootstrap 5
- 15 tablas, 10 procedures, 9 roles MySQL

## Arquitectura (MVVM)
- **Model:** `models.py`
- **View:** `templates/**/*.html`
- **ViewModel:** `main.py` (rutas Flask + helpers de validación)
- **Persistencia:** `BASE_DE_DATOS_RICARDO_ALONSO_HEALTHGUARD_PRO_1.sql`

## Instalación
```bash
pip install -r requirements.txt
mysql -u root -p < BASE_DE_DATOS_RICARDO_ALONSO_HEALTHGUARD_PRO_1.sql
# Ajustar credenciales en main.py (SQLALCHEMY_DATABASE_URI)
python reset_passwords.py
python main.py
