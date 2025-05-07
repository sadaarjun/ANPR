import os
import logging
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Database file path
db_path = 'instance/anpr.db'

# Make sure 'instance' directory exists
os.makedirs('instance', exist_ok=True)

def migrate_database():
    """Add token authentication fields to User table and flat_unit_number to Vehicle table"""
    try:
        logging.info(f"Checking if database file exists: {db_path}")
        if not os.path.exists(db_path):
            logging.warning(f"Database file not found: {db_path}")
            return False
        
        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if auth_token column exists in user table
        cursor.execute("PRAGMA table_info(user)")
        user_columns = [column[1] for column in cursor.fetchall()]
        
        if 'auth_token' not in user_columns:
            logging.info("Adding auth_token column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN auth_token VARCHAR(64)")
        else:
            logging.info("auth_token column already exists")
            
        if 'token_expiration' not in user_columns:
            logging.info("Adding token_expiration column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN token_expiration TIMESTAMP")
        else:
            logging.info("token_expiration column already exists")
            
        # Check if flat_unit_number column exists in vehicle table
        cursor.execute("PRAGMA table_info(vehicle)")
        vehicle_columns = [column[1] for column in cursor.fetchall()]
        
        if 'flat_unit_number' not in vehicle_columns:
            logging.info("Adding flat_unit_number column to vehicle table...")
            cursor.execute("ALTER TABLE vehicle ADD COLUMN flat_unit_number VARCHAR(50)")
        else:
            logging.info("flat_unit_number column already exists")
            
        # Commit the changes
        conn.commit()
        logging.info("Database migration completed successfully")
        
        # Close the connection
        conn.close()
        return True
    except Exception as e:
        logging.error(f"Error during database migration: {str(e)}")
        return False

if __name__ == "__main__":
    if migrate_database():
        logging.info("Database migration completed successfully.")
    else:
        logging.error("Database migration failed.")
