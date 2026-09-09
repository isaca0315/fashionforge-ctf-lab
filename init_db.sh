#!/bin/bash

# Initialize database for API server
cd /app

# Ensure instance directory exists and is writable
mkdir -p /app/instance
chmod 777 /app/instance


echo "Initializing database..."

python << 'EOF'
import os
import sys

# Ensure we're using the correct paths
sys.path.insert(0, '/app')

from app import app, db, init_db

with app.app_context():
    try:
        db_path = 'instance/fashion.db'
        if os.path.exists(db_path):
            print(f"Database already exists at {db_path}, keeping existing data")
        else:
            print(f"No database found at {db_path}, creating a new one")

        # Ensure tables exist without destroying existing data
        print("Creating database tables (if missing)...")
        db.create_all()
        print("Database tables ready")
        
        # Initialize with sample data only if needed
        print("Initializing sample data if database is empty...")
        init_db()
        print("Database initialization complete!")
    except Exception as e:
        print(f"Error initializing database: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

EOF

exit_code=$?
if [ $exit_code -eq 0 ]; then
    echo "Database ready"
else
    echo "Database initialization failed"
    exit 1
fi
