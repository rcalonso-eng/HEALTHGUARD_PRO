# 🏥 HealthGuard Pro - Sistema de Monitoreo Médico Inteligente

**HealthGuard Pro** es una aplicación web desarrollada para la gestión clínica, el monitoreo de signos vitales y la administración de personal médico y pacientes. El sistema implementa un control de acceso basado en roles (RBAC), auditoría de acciones y respaldos de seguridad.

> **Proyecto de Tesis** - Maestría en Sistemas Computacionales  
> **Autor:** Ricardo Cesar Alonso Bravo  
> **Materia:** Lenguajes Web - Tercer Semestre

---

## 🏗️ Arquitectura y Patrón de Diseño (MVVM)

Aunque el sistema está desarrollado sobre **Flask (Python)**, se ha adaptado la implementación siguiendo los principios del patrón **Modelo-Vista-VistaModelo (MVVM)** para garantizar la separación de responsabilidades:

*   **Modelo (Model):** Implementado en `models.py` utilizando `Flask-SQLAlchemy`. Define la estructura de la base de datos, las relaciones y las reglas de persistencia (ej. encriptación de contraseñas).
*   **Vista (View):** Implementado en la carpeta `templates/` con `Jinja2` y HTML5. Es la capa puramente visual que interactúa con el usuario final.
*   **VistaModelo (ViewModel / Controlador):** Implementado en `main.py`. Actúa como el orquestador: recibe las peticiones HTTP, aplica la lógica de negocio (como las validaciones clínicas de los signos vitales) y prepara los datos para ser renderizados por las Vistas.

### 📂 Estructura del Proyecto

```text
healthguard_pro/
│
├── app/  (o raíz del proyecto)
│   ├── models.py           # MODELO: Estructura de la base de datos y lógica de negocio
│   ├── main.py             # VIEWMODEL/CONTROLADOR: Rutas, validaciones y lógica de enrutamiento
│   ├── reset_passwords.py  # Script de utilidad para pruebas
│   ├── static/             # VISTA: Recursos estáticos (CSS, JS, imágenes)
│   │   ├── css/
│   │   └── js/
│   └── templates/          # VISTA: Plantillas HTML (Jinja2)
│       ├── auth/
│       ├── pacientes/
│       ├── signos/
│       ├── base.html       # Template principal (layout)
│       └── ...
│
├── BASE_DE_DATOS_RICARDO_ALONSO_HEALTHGUARD_PRO_1.sql  # Script de creación de BD
├── requirements.txt        # Dependencias del proyecto
└── README.md               # Documentación del proyecto