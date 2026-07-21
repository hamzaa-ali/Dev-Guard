import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dashboard.app import create_app
from shared.models import db

app = create_app()
with app.app_context():
    with db.engine.connect() as conn:
        conn.execute(db.text(
            'ALTER TABLE repos ADD COLUMN IF NOT EXISTS '
            'blocked_pushes INTEGER DEFAULT 0'
        ))
        conn.commit()
    print('✅ blocked_pushes column added to repos table')