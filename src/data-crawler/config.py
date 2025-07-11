import os
import socket
from dotenv import load_dotenv

load_dotenv()

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'domain_network'),
    'port': int(os.getenv('DB_PORT', 3306))
}

# Collection configuration
COLLECTION_CONFIG = {
    'timeout': int(os.getenv('COLLECTION_TIMEOUT', 30)),
    'request_delay': float(os.getenv('COLLECTION_REQUEST_DELAY', 1)),  # Delay between requests in seconds
    'max_links_per_page': int(os.getenv('COLLECTION_MAX_LINKS_PER_PAGE', 50)),
    'max_urls_per_domain': int(os.getenv('COLLECTION_MAX_URLS_PER_DOMAIN', 10)),
    'max_depth': int(os.getenv('COLLECTION_MAX_DEPTH', 3)),  # Maximum crawl depth
    'skip_already_processed': os.getenv('COLLECTION_SKIP_ALREADY_PROCESSED', 'True').lower() == 'true',
    'http_user_agent': os.getenv('COLLECTION_HTTP_USER_AGENT', 'WorldMapper/1.0 (compatible)'),
    'internal_agent_name': os.getenv('COLLECTION_INTERNAL_AGENT_NAME', f"{os.uname().nodename}-{os.getpid()}"),
    'respect_robots_txt': os.getenv('COLLECTION_RESPECT_ROBOTS_TXT', 'True').lower() == 'true',
    'parallel_workers': int(os.getenv('COLLECTION_PARALLEL_WORKERS', 1)),  # Number of parallel workers
}

# Data collection configuration
DATA_CONFIG = {
    'collect_whois': os.getenv('COLLECT_WHOIS', 'True').lower() == 'true',
    'collect_ssl': os.getenv('COLLECT_SSL', 'True').lower() == 'true',
    'collect_geolocation': os.getenv('COLLECT_GEOLOCATION', 'True').lower() == 'true',
    'collect_screenshots': os.getenv('COLLECT_SCREENSHOTS', 'False').lower() == 'true',
    'maxmind_db_path': os.getenv('MAXMIND_DB_PATH', './resources/data-crawler/GeoLite2-City.mmdb'),
    'screenshot_dir': os.getenv('SCREENSHOT_DIR', './resources/screenshots'),
    'ipinfo_fallback': os.getenv('IPINFO_FALLBACK', 'True').lower() == 'true',
    'ipinfo_token': os.getenv('IPINFO_TOKEN', None),
}

# Auto-update configuration
AUTO_UPDATE_CONFIG = {
    'enabled': os.getenv('AUTO_UPDATE_ENABLED', 'true').lower() in ('true', '1', 'yes'),  # Enable or disable auto-update (default: true)
    'repo_url': os.getenv('AUTO_UPDATE_REPO_URL', 'https://github.com/Rabenherz112/map-the-net.git'),  # Repository URL to check for updates
    'check_interval': int(os.getenv('AUTO_UPDATE_CHECK_INTERVAL', '21600')),  # How often to check for updates (seconds, default: 6h)
    'only_on_release': os.getenv('AUTO_UPDATE_ONLY_ON_RELEASE', 'false').lower() in ('true', '1', 'yes'),  # Only update on new releases (default: false)
    'release_keywords': [k.strip() for k in os.getenv('AUTO_UPDATE_RELEASE_KEYWORDS', 'CW-PUSH,ALL-PUSH,PUSH').split(',') if k.strip()],  # Only update if release name contains one of these keywords (comma-separated, default: 'CW-PUSH,ALL-PUSH,PUSH')
    'auth_token': os.getenv('AUTO_UPDATE_AUTH_TOKEN', None),  # Auth token for private repos (optional)
    'include_prereleases': os.getenv('AUTO_UPDATE_INCLUDE_PRERELEASES', 'false').lower() in ('true', '1', 'yes'),  # Include pre-releases in update checks (default: false)
}