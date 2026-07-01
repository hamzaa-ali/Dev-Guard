from dashboard.app import create_app
from shared.models import db, User

app = create_app()

with app.app_context():
    # This creates all tables in PostgreSQL based on your models
    db.create_all()
    print("✅ All tables created successfully.")

    # Create one default admin user so you can log in
    existing = User.query.filter_by(username='admin').first()
    if not existing:
        admin = User(username='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("✅ Default admin user created. Username: admin | Password: admin123")
    else:
        print("ℹ️  Admin user already exists, skipping.")