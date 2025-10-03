# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Ikhlas

from app import app, db
from werkzeug.security import generate_password_hash


def initialize_database():
    print("Starting database initialization...")

    with app.app_context():
        # Drop all existing tables
        print("Dropping existing database tables...")
        db.drop_all()

        # Create all tables
        print("Creating new database tables...")
        db.create_all()

        # Create default admin user
        from app import User
        print("Creating default admin user...")
        admin = User(
            username='admin',
            name='Administrator',
            password=generate_password_hash('admin123')
        )
        try:
            db.session.add(admin)
            db.session.commit()
            print("✓ Default admin user created successfully")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating admin user: {str(e)}")

        print("\nDatabase initialization completed!")


if __name__ == "__main__":
    initialize_database()