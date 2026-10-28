"""
SQLite database initialization with seed users (admin, officer, public).
Run this after creating the tables: python init_db.py
"""
from models import Base, engine, SessionLocal, User
from auth import hash_password

def init_db():
    """Create tables and seed initial users."""
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    # Check if users already exist
    existing = db.query(User).count()
    if existing > 0:
        print("✓ Database already initialized with users. Skipping seed.")
        db.close()
        return
    
    # Seed users with roles
    seed_users = [
        {
            "email": "public@crimewatch.ke",
            "name": "Public User",
            "role": "public",
            "password": "public123"
        },
        {
            "email": "officer@crimewatch.ke",
            "name": "Officer Kamau",
            "role": "officer",
            "password": "officer123"
        },
        {
            "email": "admin@crimewatch.ke",
            "name": "Admin Imran",
            "role": "admin",
            "password": "admin123"
        }
    ]
    
    for user_data in seed_users:
        user = User(
            email=user_data["email"],
            name=user_data["name"],
            role=user_data["role"],
            password_hash=hash_password(user_data["password"]),
            is_active=True
        )
        db.add(user)
        print(f"  • Created {user_data['role']:8} → {user_data['email']}")
    
    db.commit()
    db.close()
    
    print("\n✓ Database initialized successfully!")
    print("\n📋 Test Credentials:")
    print("  public@crimewatch.ke    / public123   (View reports only)")
    print("  officer@crimewatch.ke   / officer123  (Investigate & assign)")
    print("  admin@crimewatch.ke     / admin123    (Full access)")

if __name__ == "__main__":
    init_db()
