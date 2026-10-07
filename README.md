# CyberSentinel

Mini-SIEM hecho con FastAPI y SQLAlchemy. Recibe logs de eventos de login, los analiza con reglas de detección y genera alertas que se ven en un dashboard web.

## Reglas de detección
- Fuerza bruta: 5 o más logins fallidos en 5 minutos desde la misma IP
- Password spraying: una IP probando 4 o más usuarios distintos en 5 minutos
- IP en lista negra (editable desde el dashboard)
- Login exitoso fuera de horario (00:00 a 05:59, hora de Chile)
- Login exitoso después de varios intentos fallidos

## Cómo usarlo
1. Crear el entorno e instalar dependencias:

   python -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt

2. Doble clic en `iniciar.bat` (o correr `python -m uvicorn app.main:app`)
3. Abrir http://127.0.0.1:8000

Desde el dashboard puedes simular ataques, enviar logs a mano y administrar la lista negra.

## Tecnologías
Python, FastAPI, SQLAlchemy, SQLite, HTML/JS