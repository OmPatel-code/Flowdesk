import os
from app import app, init_db, start_scheduler

# Initialize database
with app.app_context():
    init_db()

# Start scheduler only once (not in reloader)
if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
    start_scheduler()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
