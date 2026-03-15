"""
Render startup shim — runs init_db and scheduler before gunicorn serves requests.
Gunicorn imports this file as: gunicorn wsgi:app
"""
from app import app, init_db, start_scheduler

# Initialise database tables and seed users on first deploy
with app.app_context():
    init_db()

# Start the background email scheduler
start_scheduler()
