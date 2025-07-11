import mysql.connector
from mysql.connector import Error
import logging
from config import DB_CONFIG

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        self.connection = None
        self.connect()
        self.create_tables()
    
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = mysql.connector.connect(**DB_CONFIG)
            logger.info("Database connection established successfully")
        except Error as e:
            logger.error(f"Error connecting to MySQL: {e}")
            raise
    
    def create_tables(self):
        """Create necessary tables if they don't exist"""
        try:
            cursor = self.connection.cursor()
            
            # Domains table with enhanced fields
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS domains (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    domain_name VARCHAR(255) UNIQUE NOT NULL,
                    title VARCHAR(500),
                    description TEXT,
                    favicon_url VARCHAR(500),
                    created_date DATE,
                    expiry_date DATE,
                    registrar VARCHAR(255),
                    nameservers TEXT,
                    asn VARCHAR(50),
                    asn_description VARCHAR(500),
                    ssl_valid BOOLEAN,
                    ssl_expiry DATE,
                    country VARCHAR(100),
                    ip_address VARCHAR(45),
                    latitude DECIMAL(10, 8),
                    longitude DECIMAL(11, 8),
                    screenshot_path VARCHAR(500),
                    category VARCHAR(100),
                    tags TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_domain_name (domain_name),
                    INDEX idx_category (category),
                    INDEX idx_created_date (created_date),
                    INDEX idx_asn (asn),
                    INDEX idx_registrar (registrar)
                )
            """)
            
            # Relationships table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS relationships (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    source_domain_id INT,
                    target_domain_id INT,
                    relationship_type ENUM('link', 'redirect', 'subdomain', 'related') DEFAULT 'link',
                    link_text VARCHAR(500),
                    link_url VARCHAR(500),
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (source_domain_id) REFERENCES domains(id) ON DELETE CASCADE,
                    FOREIGN KEY (target_domain_id) REFERENCES domains(id) ON DELETE CASCADE,
                    UNIQUE KEY unique_relationship (source_domain_id, target_domain_id, relationship_type),
                    INDEX idx_source_domain (source_domain_id),
                    INDEX idx_target_domain (target_domain_id),
                    INDEX idx_relationship_type (relationship_type)
                )
            """)
            
            # Discovery queue table for auto-discovered URLs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS discovery_queue (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    url VARCHAR(500) NOT NULL,
                    domain_name VARCHAR(255),
                    source_domain_id INT,
                    priority INT DEFAULT 1,
                    status ENUM('pending', 'processing', 'completed', 'failed', 'skipped') DEFAULT 'pending',
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    queued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed_at TIMESTAMP NULL,
                    error_message TEXT,
                    depth INT DEFAULT 0,
                    FOREIGN KEY (source_domain_id) REFERENCES domains(id) ON DELETE SET NULL,
                    INDEX idx_status (status),
                    INDEX idx_priority (priority),
                    INDEX idx_domain_name (domain_name),
                    INDEX idx_discovered_at (discovered_at),
                    UNIQUE KEY unique_url (url)
                )
            """)
            
            # Collection logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collection_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    domain_name VARCHAR(255),
                    status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
                    error_message TEXT,
                    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processing_time DECIMAL(10, 3),
                    relationships_found INT DEFAULT 0,
                    urls_discovered INT DEFAULT 0,
                    INDEX idx_status (status),
                    INDEX idx_collected_at (collected_at)
                )
            """)
            
            # URL processing history table to track processed URLs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS url_processing_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    url VARCHAR(500) NOT NULL,
                    domain_name VARCHAR(255),
                    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status ENUM('success', 'failed', 'skipped') DEFAULT 'success',
                    links_found INT DEFAULT 0,
                    INDEX idx_url (url),
                    INDEX idx_domain_name (domain_name),
                    INDEX idx_processed_at (processed_at),
                    UNIQUE KEY unique_url_history (url)
                )
            """)
            
            self.connection.commit()
            logger.info("Database tables created successfully")
            
        except Error as e:
            logger.error(f"Error creating tables: {e}")
            raise
        finally:
            if cursor:
                cursor.close()
    
    def insert_domain(self, domain_data):
        """Insert or update domain information"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO domains (
                    domain_name, title, description, favicon_url, created_date, 
                    expiry_date, registrar, nameservers, asn, asn_description,
                    ssl_valid, ssl_expiry, country, ip_address, latitude, 
                    longitude, screenshot_path, category, tags
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) ON DUPLICATE KEY UPDATE
                    title = VALUES(title),
                    description = VALUES(description),
                    favicon_url = VALUES(favicon_url),
                    created_date = VALUES(created_date),
                    expiry_date = VALUES(expiry_date),
                    registrar = VALUES(registrar),
                    nameservers = VALUES(nameservers),
                    asn = VALUES(asn),
                    asn_description = VALUES(asn_description),
                    ssl_valid = VALUES(ssl_valid),
                    ssl_expiry = VALUES(ssl_expiry),
                    country = VALUES(country),
                    ip_address = VALUES(ip_address),
                    latitude = VALUES(latitude),
                    longitude = VALUES(longitude),
                    screenshot_path = VALUES(screenshot_path),
                    category = VALUES(category),
                    tags = VALUES(tags),
                    updated_at = CURRENT_TIMESTAMP
            """
            
            cursor.execute(query, (
                domain_data.get('domain_name'),
                domain_data.get('title'),
                domain_data.get('description'),
                domain_data.get('favicon_url'),
                domain_data.get('created_date'),
                domain_data.get('expiry_date'),
                domain_data.get('registrar'),
                domain_data.get('nameservers'),
                domain_data.get('asn'),
                domain_data.get('asn_description'),
                domain_data.get('ssl_valid'),
                domain_data.get('ssl_expiry'),
                domain_data.get('country'),
                domain_data.get('ip_address'),
                domain_data.get('latitude'),
                domain_data.get('longitude'),
                domain_data.get('screenshot_path'),
                domain_data.get('category'),
                domain_data.get('tags')
            ))
            
            domain_id = cursor.lastrowid
            self.connection.commit()
            logger.info(f"Domain {domain_data.get('domain_name')} inserted/updated with ID: {domain_id}")
            return domain_id
            
        except Error as e:
            logger.error(f"Error inserting domain: {e}")
            self.connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
    
    def insert_relationship(self, source_domain_id, target_domain_id, relationship_data):
        """Insert relationship between domains"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO relationships (
                    source_domain_id, target_domain_id, relationship_type, 
                    link_text, link_url
                ) VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    link_text = VALUES(link_text),
                    link_url = VALUES(link_url)
            """
            
            cursor.execute(query, (
                source_domain_id,
                target_domain_id,
                relationship_data.get('type', 'link'),
                relationship_data.get('link_text'),
                relationship_data.get('link_url')
            ))
            
            self.connection.commit()
            
        except Error as e:
            logger.error(f"Error inserting relationship: {e}")
            self.connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
    
    def add_to_discovery_queue(self, url, domain_name, source_domain_id=None, depth=0, priority=1):
        """Add URL to discovery queue"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO discovery_queue (
                    url, domain_name, source_domain_id, depth, priority
                ) VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    priority = GREATEST(discovery_queue.priority, VALUES(priority)),
                    depth = LEAST(discovery_queue.depth, VALUES(depth))
            """
            
            cursor.execute(query, (url, domain_name, source_domain_id, depth, priority))
            self.connection.commit()
            
        except Error as e:
            logger.error(f"Error adding to discovery queue: {e}")
            self.connection.rollback()
        finally:
            if cursor:
                cursor.close()
    
    def get_next_from_queue(self, limit=10):
        """Get next URLs from discovery queue"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            
            query = """
                SELECT id, url, domain_name, source_domain_id, depth, priority
                FROM discovery_queue 
                WHERE status = 'pending'
                ORDER BY priority DESC, discovered_at ASC
                LIMIT %s
            """
            
            cursor.execute(query, (limit,))
            results = cursor.fetchall()
            
            # Mark as processing
            if results:
                ids = [str(r['id']) for r in results]
                update_query = f"""
                    UPDATE discovery_queue 
                    SET status = 'processing', processed_at = CURRENT_TIMESTAMP
                    WHERE id IN ({','.join(ids)})
                """
                cursor.execute(update_query)
                self.connection.commit()
            
            return results
            
        except Error as e:
            logger.error(f"Error getting from queue: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
    
    def mark_queue_item_completed(self, queue_id, success=True, error_message=None):
        """Mark queue item as completed or failed"""
        try:
            cursor = self.connection.cursor()
            
            status = 'completed' if success else 'failed'
            query = """
                UPDATE discovery_queue 
                SET status = %s, processed_at = CURRENT_TIMESTAMP, error_message = %s
                WHERE id = %s
            """
            
            cursor.execute(query, (status, error_message, queue_id))
            self.connection.commit()
            
        except Error as e:
            logger.error(f"Error marking queue item: {e}")
            self.connection.rollback()
        finally:
            if cursor:
                cursor.close()
    
    def is_url_in_queue(self, url, exclude_id=None):
        """Check if URL is already in the discovery queue"""
        try:
            cursor = self.connection.cursor()
            if exclude_id:
                cursor.execute("SELECT id FROM discovery_queue WHERE url = %s AND status IN ('pending', 'processing') AND id != %s", (url, exclude_id))
            else:
                cursor.execute("SELECT id FROM discovery_queue WHERE url = %s AND status IN ('pending', 'processing')", (url,))
            result = cursor.fetchone()
            return result is not None
        except Error as e:
            logger.error(f"Error checking if URL is in queue: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
    
    def is_url_already_processed(self, url):
        """Check if URL has already been processed"""
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT id FROM url_processing_history WHERE url = %s", (url,))
            result = cursor.fetchone()
            return result is not None
        except Error as e:
            logger.error(f"Error checking URL processing history: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
    
    def record_url_processing(self, url, domain_name, status='success', links_found=0):
        """Record URL processing in history"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO url_processing_history (
                    url, domain_name, status, links_found
                ) VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    processed_at = CURRENT_TIMESTAMP,
                    status = VALUES(status),
                    links_found = VALUES(links_found)
            """
            
            cursor.execute(query, (url, domain_name, status, links_found))
            self.connection.commit()
            
        except Error as e:
            logger.error(f"Error recording URL processing: {e}")
            self.connection.rollback()
        finally:
            if cursor:
                cursor.close()
    
    def get_domain_processing_count(self, domain_name):
        """Get count of URLs processed for a domain"""
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM url_processing_history WHERE domain_name = %s", (domain_name,))
            result = cursor.fetchone()
            return result[0] if result else 0
        except Error as e:
            logger.error(f"Error getting domain processing count: {e}")
            return 0
        finally:
            if cursor:
                cursor.close()
    
    def get_domain_id(self, domain_name):
        """Get domain ID by domain name"""
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT id FROM domains WHERE domain_name = %s", (domain_name,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Error as e:
            logger.error(f"Error getting domain ID: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
    
    def update_collection_log(self, domain_name, status, error_message=None, processing_time=None, relationships_found=0, urls_discovered=0, url=None, agent_name=None):
        """Update collection log with URL and agent information"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO collection_logs (
                    domain_name, status, error_message, processing_time, relationships_found, urls_discovered, url, agent_name
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(query, (domain_name, status, error_message, processing_time, relationships_found, urls_discovered, url, agent_name))
            self.connection.commit()
            
        except Error as e:
            logger.error(f"Error updating collection log: {e}")
            self.connection.rollback()
        finally:
            if cursor:
                cursor.close()
    
    def get_queue_stats(self):
        """Get queue statistics"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            
            query = """
                SELECT 
                    status,
                    COUNT(*) as count
                FROM discovery_queue 
                GROUP BY status
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            stats = {}
            for row in results:
                stats[row['status']] = row['count']
            
            return stats
            
        except Error as e:
            logger.error(f"Error getting queue stats: {e}")
            return {}
        finally:
            if cursor:
                cursor.close()
    
    def is_domain_data_complete(self, domain_name):
        """Check if domain already has complete data (all required fields)"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT title, description, created_date, registrar, nameservers, 
                       ssl_valid, country, ip_address, latitude, longitude
                FROM domains 
                WHERE domain_name = %s
            """, (domain_name,))
            result = cursor.fetchone()
            
            if not result:
                return False
            
            # Check if we have the essential data fields
            essential_fields = ['title', 'description', 'ip_address']
            return all(result.get(field) is not None for field in essential_fields)
            
        except Error as e:
            logger.error(f"Error checking domain data completeness: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
    
    def close(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logger.info("Database connection closed") 