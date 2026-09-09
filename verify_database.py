#!/usr/bin/env python3
"""
Database Verification Script
Verifies that both API app and OAuth server use the same database file.
"""

import os
import sys

def verify_database_config():
    """Verify database configuration in both applications"""
    
    print("=" * 60)
    print("DATABASE SHARING VERIFICATION")
    print("=" * 60)
    print()
    
    # Check config.py
    print("1. Checking API App Configuration (config.py)...")
    try:
        sys.path.insert(0, os.path.dirname(__file__))
        from config import Config
        api_db_path = Config.db_path
        api_db_uri = Config.SQLALCHEMY_DATABASE_URI
        print(f"    Database Path: {api_db_path}")
        print(f"    Database URI: {api_db_uri}")
    except Exception as e:
        print(f"    Error reading config.py: {e}")
        api_db_path = None
        api_db_uri = None
    
    print()
    
    # Check oauth_server.py
    print("2. Checking OAuth Server Configuration (oauth_server.py)...")
    oauth_db_path = None
    oauth_db_uri = None
    try:
        # Read the file and extract db_path
        oauth_file = os.path.join(os.path.dirname(__file__), 'oauth_server.py')
        with open(oauth_file, 'r') as f:
            content = f.read()
            # Find db_path assignment
            for line in content.split('\n'):
                if 'db_path = ' in line and 'fashion.db' in line:
                    oauth_db_path = line.split('=')[1].strip().strip("'\"")
                    break
            # Construct URI from path
            if oauth_db_path:
                oauth_db_uri = f"sqlite:///{oauth_db_path}"
        print(f"    Database Path: {oauth_db_path}")
        print(f"    Database URI: {oauth_db_uri}")
    except Exception as e:
        print(f"    Error reading oauth_server.py: {e}")
        oauth_db_path = None
        oauth_db_uri = None
    
    print()
    
    # Compare configurations
    print("3. Comparing Configurations...")
    print("-" * 60)
    
    if api_db_path and oauth_db_path:
        if api_db_path == oauth_db_path:
            print("    Database paths MATCH!")
            print(f"      Both use: {api_db_path}")
        else:
            print("    Database paths DO NOT MATCH!")
            print(f"      API App:    {api_db_path}")
            print(f"      OAuth:      {oauth_db_path}")
    
    if api_db_uri and oauth_db_uri:
        # Normalize URIs for comparison (remove extra slashes)
        api_normalized = api_db_uri.replace('sqlite:///', 'sqlite:///').replace('//', '/')
        oauth_normalized = oauth_db_uri.replace('sqlite:///', 'sqlite:///').replace('//', '/')
        
        if api_normalized == oauth_normalized:
            print("    Database URIs MATCH!")
        else:
            print("   Database URIs differ (but may point to same file)")
            print(f"      API App:    {api_db_uri}")
            print(f"      OAuth:      {oauth_db_uri}")
    
    print()
    
    # Check if database file exists
    print("4. Checking Database File...")
    if api_db_path:
        db_exists = os.path.exists(api_db_path)
        if db_exists:
            db_size = os.path.getsize(api_db_path)
            print(f"    Database file exists: {api_db_path}")
            print(f"    File size: {db_size:,} bytes ({db_size / (1024*1024):.2f} MB)")
        else:
            print(f"    Database file does not exist: {api_db_path}")
            print("      (This is normal if no users have been registered yet)")
    
    print()
    print("=" * 60)
    print("VERIFICATION COMPLETE")
    print("=" * 60)
    print()
    print("To test database connectivity:")
    print("  1. API App:    curl http://localhost:5000/debug/verify-database")
    print("  2. OAuth:      curl http://localhost:5001/debug/verify-database")
    print()

if __name__ == '__main__':
    verify_database_config()

