# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Ikhlas

# setup.py
from app import app, db
from werkzeug.security import generate_password_hash
import os
from datetime import datetime, timezone


def setup_database():
    with app.app_context():
        print("Starting database setup...")

        # Create instance directory if it doesn't exist
        instance_path = os.path.join(os.getcwd(), 'instance')
        if not os.path.exists(instance_path):
            os.makedirs(instance_path)
            print("Created instance directory")

        # Create static/voice_messages directory if it doesn't exist
        voice_messages_path = os.path.join(os.getcwd(), 'static', 'voice_messages')
        if not os.path.exists(voice_messages_path):
            os.makedirs(voice_messages_path)
            print("Created voice messages directory")

        # Remove existing database file
        db_path = os.path.join(instance_path, 'hospital.db')
        if os.path.exists(db_path):
            os.remove(db_path)
            print("Removed existing database")

        print("Creating new database tables...")
        db.create_all()

        # Create default admin user
        from app import User
        print("Creating default admin user...")
        try:
            admin = User(
                username='admin',
                name='Administrator',
                password=generate_password_hash('admin123'),
                voice_message=None,
                created_at=datetime.now(timezone.utc),
                last_login=None
            )
            db.session.add(admin)
            db.session.commit()
            print("✓ Admin user created successfully!")
            print("✓ Database setup completed!")
            print("\nYou can now login with:")
            print("Username: admin")
            print("Password: admin123")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating admin user: {str(e)}")


if __name__ == "__main__":
    setup_database()