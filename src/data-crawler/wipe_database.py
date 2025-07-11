#!/usr/bin/env python3
"""
Script to wipe the database and start fresh
"""

import sys
import logging
from database import DatabaseManager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def wipe_database():
    """Wipe all data from the database"""
    
    db = DatabaseManager()
    
    try:
        logger.info("Starting database wipe...")
        
        # Get table names
        cursor = db.connection.cursor()
        cursor.execute("SHOW TABLES")
        tables = [table[0] for table in cursor.fetchall()]
        
        logger.info(f"Found tables: {tables}")
        
        # Disable foreign key checks temporarily
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
        
        # Truncate all tables
        for table in tables:
            try:
                cursor.execute(f"TRUNCATE TABLE {table}")
                logger.info(f"Truncated table: {table}")
            except Exception as e:
                logger.warning(f"Could not truncate {table}: {e}")
        
        # Re-enable foreign key checks
        cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
        
        # Reset auto-increment counters
        for table in tables:
            try:
                cursor.execute(f"ALTER TABLE {table} AUTO_INCREMENT = 1")
                logger.info(f"Reset auto-increment for: {table}")
            except Exception as e:
                logger.warning(f"Could not reset auto-increment for {table}: {e}")
        
        db.connection.commit()
        logger.info("Database wipe completed successfully!")
        
        # Show final table status
        cursor.execute("SELECT COUNT(*) as count FROM domains")
        domain_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as count FROM relationships")
        relationship_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as count FROM discovery_queue")
        queue_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as count FROM collection_logs")
        log_count = cursor.fetchone()[0]
        
        logger.info(f"Final counts:")
        logger.info(f"  Domains: {domain_count}")
        logger.info(f"  Relationships: {relationship_count}")
        logger.info(f"  Queue items: {queue_count}")
        logger.info(f"  Collection logs: {log_count}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error wiping database: {e}")
        return False
    
    finally:
        db.close()

def confirm_wipe():
    """Ask for confirmation before wiping"""
    print("\n⚠️  WARNING: This will delete ALL data from the database!")
    print("This action cannot be undone.")
    print("\nTables that will be wiped:")
    print("  - domains")
    print("  - relationships") 
    print("  - discovery_queue")
    print("  - collection_logs")
    print("  - url_processing_logs")
    
    response = input("\nAre you sure you want to continue? (yes/no): ")
    return response.lower() in ['yes', 'y']

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--force":
        # Skip confirmation if --force flag is used
        success = wipe_database()
    else:
        if confirm_wipe():
            success = wipe_database()
        else:
            logger.info("Database wipe cancelled by user")
            success = True
    
    if success:
        logger.info("Database wipe completed successfully!")
        sys.exit(0)
    else:
        logger.error("Database wipe failed!")
        sys.exit(1) 