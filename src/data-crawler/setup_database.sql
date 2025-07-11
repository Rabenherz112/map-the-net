-- Setup script for Domain Network Database
-- Run this as MySQL root user

-- Create database
CREATE DATABASE IF NOT EXISTS domain_network CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user (replace 'your_password' with a secure password)
CREATE USER IF NOT EXISTS 'domain_collector'@'localhost' IDENTIFIED BY 'your_password';

-- Grant permissions
GRANT ALL PRIVILEGES ON domain_network.* TO 'domain_collector'@'localhost';

-- Grant permissions for remote connections (if needed)
-- GRANT ALL PRIVILEGES ON domain_network.* TO 'domain_collector'@'%';

-- Flush privileges
FLUSH PRIVILEGES;

-- Use the database
USE domain_network;

-- The tables will be created automatically by the Python script
-- This is just for reference

-- Domains table structure with enhanced fields:
/*
CREATE TABLE domains (
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
);
*/

-- Relationships table structure:
/*
CREATE TABLE relationships (
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
);
*/

-- Discovery queue table for auto-discovered URLs:
/*
CREATE TABLE discovery_queue (
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
);
*/

-- Collection logs table structure:
CREATE TABLE IF NOT EXISTS collection_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL,
    status ENUM('pending', 'processing', 'completed', 'failed') NOT NULL,
    error_message TEXT,
    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processing_time DECIMAL(10,3),
    relationships_found INT DEFAULT 0,
    urls_discovered INT DEFAULT 0,
    url VARCHAR(500),
    agent_name VARCHAR(100),
    INDEX idx_domain_name (domain_name),
    INDEX idx_status (status),
    INDEX idx_processed_at (processed_at),
    INDEX idx_url (url),
    INDEX idx_agent_name (agent_name)
);

SELECT 'Database setup completed successfully!' as status; 