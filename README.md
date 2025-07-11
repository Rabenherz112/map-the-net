# Domain Relationship Visualization Tool

A comprehensive domain relationship visualization tool with a data collection system that crawls domains, collects metadata (WHOIS, SSL, geolocation, screenshots), discovers relationships by crawling links, and stores data in a MySQL database. The system supports parallel and queue-based processing for scalability.

## Features

### Core Functionality
- **Domain Data Collection**: Comprehensive metadata collection including WHOIS, DNS, SSL certificates, geolocation, and screenshots
- **Relationship Discovery**: Automated link discovery and relationship mapping between domains
- **Queue-Based Processing**: Scalable processing with configurable depth limits and rate limiting
- **Database Storage**: MySQL-based storage with proper indexing and relationship tracking

### Data Collection Capabilities
- **Web Data**: Title, description, favicon extraction
- **WHOIS Data**: Domain registration information (creation date, expiry, registrar)
- **DNS Data**: IP addresses, nameservers, ASN information
- **SSL Data**: Certificate validity, expiry dates
- **Geolocation**: Country, latitude/longitude based on IP
- **Screenshots**: Visual snapshots of web pages
- **Relationship Data**: Link text, URLs, and relationship types

### Scalability Features
- **Parallel Processing**: Support for concurrent domain processing
- **Queue Management**: Intelligent queue processing with duplicate prevention
- **Depth Control**: Configurable crawl depth limits
- **Rate Limiting**: Respectful crawling with configurable delays
- **Resource Management**: Proper cleanup and error recovery

## Installation

### Prerequisites
- Python 3.8+
- MySQL 8.0+
- System `whois` command (for WHOIS data collection)

### Setup
1. Clone the repository:
```bash
git clone <repository-url>
cd map-the-net
```

2. Create virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install system WHOIS command:
```bash
# Ubuntu/Debian
sudo apt-get install whois

# CentOS/RHEL
sudo yum install whois

# macOS
brew install whois
```

5. Configure database:
```bash
# Copy environment template
cp env_example.txt .env

# Edit .env with your database credentials
# Then run database setup
mysql -u your_user -p your_database < setup_database.sql
```

## Usage

### Basic Usage

1. **Add seed domains to queue**:
```bash
python3 queue_processor.py --add-seeds example.com another-domain.com
```

2. **Process the queue**:
```bash
python3 queue_processor.py --max-items 50 --max-depth 3
```

3. **Continuous processing**:
```bash
python3 queue_processor.py --continuous --max-depth 2
```

### Advanced Usage

**Parallel Processing**:
```bash
python3 parallel_collector.py --domains domains.txt --workers 4
```

**Database Management**:
```bash
# Wipe database (use with caution!)
python3 wipe_database.py --force

# Test specific functionality
python3 test_improvements.py
```

### Configuration Data Crawler

Create a `.env` file or copy it from `env_example.txt` and set the following variables:

| Variable | Description | Default |
|----------|-------------|---------|


## Database Schema

### Core Tables
- **domains**: Domain metadata and collected data
- **relationships**: Links and relationships between domains
- **discovery_queue**: URL queue for processing
- **url_processing_history**: Processing history and statistics
- **collection_logs**: Collection status and timing

### Key Relationships
- Domains can have multiple relationships (source → target)
- Queue items track processing depth and status
- Processing history prevents duplicate work

## Troubleshooting

### Common Issues

1. **WHOIS Command Not Found**:
   ```bash
   # Install system whois command
   sudo apt-get install whois  # Ubuntu/Debian
   ```

2. **Database Connection Issues**:
   - Verify MySQL is running
   - Check credentials in `.env` file
   - Ensure database exists and user has permissions

3. **Rate Limiting**:
   - Increase `request_delay` in config
   - Reduce `max_items` for slower processing

4. **Memory Issues**:
   - Reduce `max_links_per_page`
   - Lower `max_depth` for shallower crawling

### Debugging

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Test specific components:
```bash
python3 test_improvements.py
python3 test_new_logic.py example.com
```

## Performance Tips

1. **Database Optimization**:
   - Use SSD storage for MySQL
   - Increase MySQL buffer pool size
   - Add indexes on frequently queried columns

2. **Network Optimization**:
   - Use faster internet connection
   - Consider using proxies for large-scale crawling
   - Implement proper rate limiting

3. **Resource Management**:
   - Monitor memory usage during large crawls
   - Use appropriate `max_items` and `max_depth` values
   - Implement graceful shutdown for long-running processes

## License

This project is licensed under the GNU AGPL v3.0. See the [LICENSE](./LICENSE) file for details.

## Auto-Update Feature

The crawler can automatically check for updates and apply them, with options to control update behavior.

### Configuration Options

- `AUTO_UPDATE_ENABLED` (default: `true`): Enable or disable auto-update.
- `AUTO_UPDATE_REPO_URL` (default: your repo URL): The repository to check for updates.
- `AUTO_UPDATE_CHECK_INTERVAL` (default: 21600): How often (in seconds) to check for updates.
- `AUTO_UPDATE_ONLY_ON_RELEASE` (default: `false`): Only update on new releases.
- `AUTO_UPDATE_RELEASE_KEYWORDS` (default: empty): Only update if release name contains one of these keywords (comma-separated).
- `AUTO_UPDATE_AUTH_TOKEN` (optional): Auth token for private repos.

### How it Works

- On startup and at regular intervals, the crawler checks for updates.
- If an update is available (and matches config), it will gracefully shut down, update, and restart with the same parameters (excluding `--add-seeds`).
- Supports git, release, and file-based deployments.

See `src/data-crawler/auto_update.py` for implementation details.
