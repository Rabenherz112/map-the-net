import requests
import time
import logging
import re
import socket
import ssl
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup, Tag
import whois
import tldextract
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
import dns.resolver
from config import COLLECTION_CONFIG, DATA_CONFIG, AUTO_UPDATE_CONFIG
from database import DatabaseManager
import os
from datetime import datetime, date
import json
import geoip2.database
from version import __version__
from auto_update import AutoUpdate, default_restart_callback

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DomainCollector:
    def __init__(self):
        """Initialize the domain collector"""
        self.db = DatabaseManager()
        self.db.connect()
        self.db.create_tables()
        
        # Initialize requests session with proper headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': COLLECTION_CONFIG['http_user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Initialize geolocator
        try:
            nominatim_url = DATA_CONFIG.get('nominatim_url')
            if nominatim_url:
                self.geolocator = Nominatim(user_agent=COLLECTION_CONFIG['http_user_agent'], domain=nominatim_url)
            else:
                self.geolocator = Nominatim(user_agent=COLLECTION_CONFIG['http_user_agent'])
        except Exception as e:
            logger.warning(f"Failed to initialize geolocator: {e}")
            self.geolocator = None
        
        # Initialize MaxMind GeoIP2/GeoLite2 reader
        try:
            self.maxmind_reader = geoip2.database.Reader(DATA_CONFIG['maxmind_db_path'])
        except Exception as e:
            logger.warning(f'Failed to initialize MaxMind GeoIP2: {e}')
            self.maxmind_reader = None
        
        # Initialize URL filters
        self._init_url_filters()
    
    def _init_url_filters(self):
        """Initialize URL filtering patterns"""
        # File extensions to exclude
        self.excluded_extensions = {
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp', '.ico',
            # Documents
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf',
            # Archives
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            # Media
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.wav', '.ogg',
            # Executables
            '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm',
            # Code files
            '.js', '.css', '.xml', '.json', '.csv', '.sql',
            # Other
            '.log', '.tmp', '.bak', '.old', '.cache'
        }
        
        # URL patterns to exclude
        self.excluded_patterns = [
            # Social media and tracking
            #r'facebook\.com', r'twitter\.com', r'linkedin\.com', r'instagram\.com',
            #r'google\.com/analytics', r'googletagmanager\.com', r'googleadservices\.com',
            #r'facebook\.com/plugins', r'twitter\.com/intent',
            # Common tracking and analytics
            r'analytics', r'tracking', r'pixel', r'beacon',
            # Common CDN and static content
            #r'cdn\.', r'static\.', r'assets\.', r'images\.', r'img\.',
            # Common API endpoints
            r'/api/', r'/rest/', r'/graphql', r'/swagger', r'/docs',
            # Common admin and system paths
            r'/admin', r'/wp-admin', r'/phpmyadmin', r'/cpanel',
            # Common utility paths
            r'/sitemap', r'/robots\.txt', r'/favicon\.ico',
            # Common e-commerce paths
            r'/cart', r'/checkout', r'/payment', r'/order',
            # Common user account paths
            r'/login', r'/logout', r'/register', r'/signup', r'/profile',
            # Common search and filter paths
            r'/search', r'/filter', r'/sort', r'/page',
            # Common utility paths
            r'/contact', r'/about', r'/privacy', r'/terms', r'/help'
            # Exlude Website UGC
            r'\.itch\.io', r'\.github\.io'
        ]
        
        # Compile regex patterns
        self.excluded_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.excluded_patterns]
    
    def _should_exclude_url(self, url, link_text):
        """Check if URL should be excluded based on various criteria"""
        try:
            parsed_url = urlparse(url)
            
            # Skip if no netloc (relative links, javascript, etc.)
            if not parsed_url.netloc:
                return True, "No domain"
            
            # Check for excluded file extensions
            path = parsed_url.path.lower()
            for ext in self.excluded_extensions:
                if path.endswith(ext):
                    return True, f"Excluded extension: {ext}"
            
            # Check for excluded patterns
            full_url = url.lower()
            for pattern in self.excluded_regex:
                if pattern.search(full_url):
                    return True, f"Excluded pattern: {pattern.pattern}"
            
            # Skip URLs with excessive parameters (likely tracking)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                if len(query_params) > 10:  # Too many parameters
                    return True, "Too many query parameters"
                
                # Check for common tracking parameters
                tracking_params = ['utm_', 'fbclid', 'gclid', 'ref', 'source', 'campaign']
                for param in query_params.keys():
                    if any(tracking in param.lower() for tracking in tracking_params):
                        return True, f"Tracking parameter: {param}"
            
            # Skip very long URLs (likely generated)
            if len(url) > 500:
                return True, "URL too long"
            
            # Skip URLs with excessive path segments
            path_segments = [seg for seg in parsed_url.path.split('/') if seg]
            if len(path_segments) > 8:
                return True, "Too many path segments"
            
            # Skip URLs with common non-content paths
            if path_segments:
                first_segment = path_segments[0].lower()
                non_content_paths = ['api', 'admin', 'assets', 'static', 'cdn', 'images', 'img', 'css', 'js']
                if first_segment in non_content_paths:
                    return True, f"Non-content path: {first_segment}"
            
            # Skip empty or very short link text (likely not meaningful)
            if not link_text or len(link_text.strip()) < 2:
                return True, "Empty or very short link text"
            
            # Skip common non-content link texts
            non_content_texts = ['click here', 'read more', 'learn more', 'continue', 'next', 'previous']
            if link_text.lower().strip() in non_content_texts:
                return True, f"Non-content link text: {link_text}"
            
            return False, None
            
        except Exception as e:
            logger.warning(f"Error checking URL exclusion: {e}")
            return True, f"Error checking URL: {e}"
    
    def _clean_url_for_queue(self, url):
        """Clean URL by removing parameters and fragments for queue processing"""
        try:
            parsed_url = urlparse(url)
            
            # Remove query parameters and fragments
            clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Remove trailing slash for consistency
            if clean_url.endswith('/') and len(clean_url) > 1:
                clean_url = clean_url.rstrip('/')
            
            return clean_url
            
        except Exception as e:
            logger.warning(f"Error cleaning URL: {e}")
            return url
    
    def _get_main_domain(self, domain_name):
        """Extract the main domain for WHOIS queries (remove subdomains)"""
        parts = domain_name.split('.')
        if len(parts) > 2:
            # For domains like blog.theravenhub.com, return theravenhub.com
            return '.'.join(parts[-2:])
        return domain_name
    
    def _is_allowed_to_scrape(self, domain_name, path='/'):
        """Check if scraping is allowed for the given domain and path using robots.txt logic."""
        return self._check_robots_txt(domain_name, path)
    
    def collect_domain_data(self, domain_name, depth=0, url=None, shutdown_check=None):
        """Collect comprehensive data for a domain"""
        start_time = time.time()
        # Ensure url is always defined
        if url is None:
            url = f"http://{domain_name}"
        try:
            # Check for shutdown at the start
            if shutdown_check and shutdown_check():
                logger.info("Shutdown requested at start of domain collection")
                return None, []
            
            logger.info(f"Starting collection for domain: {domain_name}")
            self.db.update_collection_log(domain_name, 'processing', url=url, agent_name=COLLECTION_CONFIG['internal_agent_name'])
            
            # Check if domain already has complete data
            if self.db.is_domain_data_complete(domain_name):
                logger.info(f"Domain {domain_name} already has complete data, skipping collection")
                domain_id = self.db.get_domain_id(domain_name)
                if not domain_id:
                    # Insert basic domain record if not exists
                    domain_data = {'domain_name': domain_name, 'status': 'completed'}
                    domain_id = self.db.insert_domain(domain_data)
                
                # Check for shutdown before relationship collection
                if shutdown_check and shutdown_check():
                    logger.info("Shutdown requested before relationship collection")
                    return domain_id, []
                
                # Still collect relationships and discover URLs
                relationships, discovered_urls = self._collect_relationships_and_discover(domain_name, domain_id, shutdown_check)
                
                # Add discovered URLs to queue for future processing
                if discovered_urls:
                    self.add_discovered_urls_to_queue(discovered_urls, depth + 1)
                
                processing_time = time.time() - start_time
                self.db.update_collection_log(
                    domain_name, 'completed', 
                    processing_time=processing_time,
                    relationships_found=len(relationships),
                    urls_discovered=len(discovered_urls),
                    url=url,
                    agent_name=COLLECTION_CONFIG['internal_agent_name']
                )
                
                logger.info(f"Successfully processed {domain_name} (existing data) in {processing_time:.2f}s")
                return domain_id, relationships
            
            # Check for shutdown before full collection
            if shutdown_check and shutdown_check():
                logger.info("Shutdown requested before full domain collection")
                return None, []
            
            domain_data = {
                'domain_name': domain_name,
                'title': None,
                'description': None,
                'favicon_url': None,
                'created_date': None,
                'expiry_date': None,
                'registrar': None,
                'nameservers': None,
                'asn': None,
                'asn_description': None,
                'ssl_valid': None,
                'ssl_expiry': None,
                'country': None,
                'ip_address': None,
                'latitude': None,
                'longitude': None,
                'screenshot_path': None,
                'category': None,
                'tags': None
            }
            
            # Collect basic web data
            web_data = self._collect_web_data(domain_name)
            domain_data.update(web_data)

            # --- Simple Category and Tags Logic ---
            title = web_data.get('title', '') or ''
            description = web_data.get('description', '') or ''
            category = None
            tags = set()

            # Heuristic for category (expanded)
            lowered = f"{title} {description} {domain_name}".lower()
            if 'blog' in lowered or 'post' in lowered or 'journal' in lowered:
                category = 'blog'
            elif any(word in lowered for word in ['shop', 'store', 'buy', 'ecommerce', 'cart', 'product', 'sale', 'deal', 'outlet', 'retail', 'market']):
                category = 'ecommerce'
            elif any(word in lowered for word in ['news', 'media', 'press', 'magazine', 'gazette', 'bulletin', 'headline', 'reporter', 'newspaper']):
                category = 'news'
            elif any(word in lowered for word in ['forum', 'community', 'discussion', 'board', 'thread', 'topic', 'messageboard', 'chat']):
                category = 'forum'
            elif any(word in lowered for word in ['university', 'college', 'school', 'edu', 'academy', 'institute', 'campus', 'faculty', 'student', 'alumni']):
                category = 'education'
            elif any(word in lowered for word in ['gov', 'government', 'municipal', 'state', 'federal', 'ministry', 'council', 'parliament', 'senate', 'congress']):
                category = 'government'
            elif any(word in lowered for word in ['wiki', 'encyclopedia', 'reference', 'dictionary', 'glossary', 'manual', 'howto', 'faq']):
                category = 'reference'
            elif any(word in lowered for word in ['portfolio', 'resume', 'cv', 'bio', 'aboutme', 'profile', 'personal', 'homepage']):
                category = 'personal'
            elif any(word in lowered for word in ['software', 'app', 'download', 'tool', 'platform', 'service', 'cloud', 'saas', 'opensource']):
                category = 'software'
            elif any(word in lowered for word in ['health', 'medical', 'clinic', 'hospital', 'doctor', 'pharmacy', 'wellness', 'care', 'medicine', 'dental', 'therapy']):
                category = 'health'
            elif any(word in lowered for word in ['finance', 'bank', 'money', 'loan', 'credit', 'investment', 'fund', 'insurance', 'mortgage', 'accounting', 'tax']):
                category = 'finance'
            elif any(word in lowered for word in ['travel', 'hotel', 'flight', 'tourism', 'trip', 'tour', 'booking', 'destination', 'holiday', 'cruise', 'airline']):
                category = 'travel'
            elif any(word in lowered for word in ['restaurant', 'food', 'cafe', 'bar', 'dining', 'menu', 'cuisine', 'eatery', 'bistro', 'pub', 'grill', 'kitchen']):
                category = 'food'
            elif any(word in lowered for word in ['sports', 'game', 'team', 'league', 'match', 'tournament', 'score', 'athlete', 'coach', 'stadium', 'fitness', 'gym']):
                category = 'sports'
            elif any(word in lowered for word in ['art', 'gallery', 'museum', 'exhibit', 'artist', 'painting', 'sculpture', 'theatre', 'concert', 'music', 'band', 'film', 'movie', 'cinema', 'festival']):
                category = 'arts'
            elif any(word in lowered for word in ['science', 'research', 'lab', 'technology', 'engineering', 'math', 'stem', 'physics', 'chemistry', 'biology', 'innovation']):
                category = 'science'
            elif any(word in lowered for word in ['real estate', 'property', 'housing', 'apartment', 'rent', 'home', 'condo', 'realtor', 'broker']):
                category = 'real_estate'
            elif any(word in lowered for word in ['job', 'career', 'employment', 'work', 'vacancy', 'recruit', 'hire', 'resume', 'cv']):
                category = 'jobs'
            elif any(word in lowered for word in ['automotive', 'car', 'vehicle', 'motor', 'auto', 'garage', 'dealer', 'truck', 'bike']):
                category = 'automotive'
            elif any(word in lowered for word in ['fashion', 'clothing', 'apparel', 'boutique', 'style', 'designer', 'shoes', 'accessory', 'jewelry']):
                category = 'fashion'
            elif any(word in lowered for word in ['kids', 'children', 'toys', 'games', 'play', 'childcare', 'nursery', 'preschool']):
                category = 'kids'
            elif any(word in lowered for word in ['environment', 'eco', 'green', 'nature', 'wildlife', 'conservation', 'sustain', 'climate']):
                category = 'environment'
            elif any(word in lowered for word in ['religion', 'church', 'temple', 'mosque', 'faith', 'spiritual', 'bible', 'quran', 'torah', 'worship']):
                category = 'religion'
            elif any(word in lowered for word in ['adult', 'sex', 'porn', 'xxx', 'escort', 'dating', 'singles']):
                category = 'adult'
            elif any(word in lowered for word in ['security', 'cyber', 'privacy', 'infosec', 'hacker', 'malware', 'virus', 'firewall']):
                category = 'security'
            elif any(word in lowered for word in ['logistics', 'shipping', 'delivery', 'supply', 'warehouse', 'freight', 'transport', 'cargo']):
                category = 'logistics'
            elif any(word in lowered for word in ['construction', 'builder', 'contractor', 'architecture', 'engineer', 'design', 'remodel', 'renovate']):
                category = 'construction'
            elif any(word in lowered for word in ['energy', 'power', 'solar', 'wind', 'electric', 'utility', 'oil', 'gas', 'nuclear']):
                category = 'energy'
            elif any(word in lowered for word in ['law', 'legal', 'attorney', 'lawyer', 'court', 'justice', 'case', 'trial', 'judge']):
                category = 'legal'
            elif any(word in lowered for word in ['consult', 'advisory', 'coach', 'mentor', 'counsel', 'strategy', 'management']):
                category = 'consulting'
            elif any(word in lowered for word in ['event', 'conference', 'expo', 'summit', 'meetup', 'webinar', 'workshop']):
                category = 'events'
            elif any(word in lowered for word in ['pet', 'animal', 'vet', 'veterinary', 'dog', 'cat', 'bird', 'fish', 'horse']):
                category = 'pets'
            elif any(word in lowered for word in ['photography', 'photo', 'camera', 'picture', 'image', 'gallery']):
                category = 'photography'
            elif any(word in lowered for word in ['translation', 'language', 'linguistics', 'dictionary', 'thesaurus', 'grammar']):
                category = 'language'
            elif any(word in lowered for word in ['hardware', 'electronics', 'gadget', 'device', 'component', 'chip', 'circuit']):
                category = 'hardware'
            elif any(word in lowered for word in ['hosting', 'server', 'domain', 'dns', 'webhost', 'cloud', 'vps']):
                category = 'hosting'
            elif any(word in lowered for word in ['printing', 'print', 'press', 'publisher', 'magazine']):
                category = 'printing'
            elif any(word in lowered for word in ['auction', 'bid', 'bidding', 'lot', 'hammer']):
                category = 'auction'
            elif any(word in lowered for word in ['charity', 'ngo', 'nonprofit', 'foundation', 'donate', 'volunteer']):
                category = 'charity'
            elif any(word in lowered for word in ['agriculture', 'farm', 'farming', 'crop', 'harvest', 'agro', 'ranch']):
                category = 'agriculture'
            elif any(word in lowered for word in ['mining', 'mine', 'miner', 'ore', 'coal', 'gold', 'silver']):
                category = 'mining'
            elif any(word in lowered for word in ['space', 'astronomy', 'planet', 'star', 'satellite', 'rocket', 'nasa']):
                category = 'space'
            elif any(word in lowered for word in ['military', 'army', 'navy', 'airforce', 'defense', 'war', 'battle']):
                category = 'military'
            elif any(word in lowered for word in ['transport', 'bus', 'train', 'metro', 'subway', 'tram', 'taxi', 'cab']):
                category = 'transport'
            elif any(word in lowered for word in ['blog', 'misc', 'other', 'general', 'info', 'site', 'web']):
                category = 'miscellaneous'
            if not category:
                category = 'miscellaneous'

            # Extract meta keywords for tags
            meta_keywords = ''
            try:
                url = f"http://{domain_name}"
                response = self.session.get(url, timeout=COLLECTION_CONFIG['timeout'])
                soup = BeautifulSoup(response.content, 'html.parser')
                meta_tag = soup.find('meta', attrs={'name': 'keywords'})
                if meta_tag and isinstance(meta_tag, Tag):
                    content = meta_tag.get('content')
                    if isinstance(content, str):
                        meta_keywords = content
            except Exception:
                pass
            if isinstance(meta_keywords, str) and meta_keywords:
                for tag in meta_keywords.split(','):
                    tag = tag.strip().lower()
                    if tag:
                        tags.add(tag)

            # Add domain parts as tags
            parts = domain_name.split('.')
            if len(parts) > 2:
                tags.add(parts[0])  # subdomain
            tags.add(parts[-2])  # main domain
            tags.add(parts[-1])  # tld

            # Add category as a tag if set
            if category:
                tags.add(category)

            # Store in domain_data
            domain_data['category'] = category
            domain_data['tags'] = ','.join(sorted(tags)) if tags else None
            
            # Collect WHOIS data (only for main domains, not subdomains)
            if DATA_CONFIG['collect_whois']:
                main_domain = self._get_main_domain(domain_name)
                if main_domain == domain_name:  # Only query WHOIS for main domains
                    whois_data = self._collect_whois_data(domain_name)
                    domain_data.update(whois_data)
                else:
                    logger.info(f"Skipping WHOIS for subdomain {domain_name}, using main domain {main_domain}")
                    # Try to get WHOIS data from main domain
                    main_domain_id = self.db.get_domain_id(main_domain)
                    if main_domain_id:
                        # Copy WHOIS data from main domain
                        cursor = self.db.connection.cursor(dictionary=True)
                        cursor.execute("""
                            SELECT created_date, expiry_date, registrar
                            FROM domains 
                            WHERE domain_name = %s
                        """, (main_domain,))
                        main_data = cursor.fetchone()
                        if main_data:
                            domain_data.update({
                                'created_date': main_data['created_date'],
                                'expiry_date': main_data['expiry_date'],
                                'registrar': main_data['registrar']
                            })
                        cursor.close()
            
            # Check for shutdown after WHOIS collection
            if shutdown_check and shutdown_check():
                logger.info("Shutdown requested after WHOIS collection")
                return None, []
            
            # Collect DNS and ASN data
            dns_data = self._collect_dns_data(domain_name)
            domain_data.update(dns_data)
            
            # Collect SSL certificate data
            if DATA_CONFIG['collect_ssl']:
                ssl_data = self._collect_ssl_data(domain_name)
                domain_data.update(ssl_data)
            
            # Collect geolocation data
            if DATA_CONFIG['collect_geolocation']:
                geo_data = self._collect_geolocation_data(domain_name)
                domain_data.update(geo_data)
            
            # Collect screenshot
            if DATA_CONFIG['collect_screenshots']:
                screenshot_path = self._take_screenshot(domain_name)
                domain_data['screenshot_path'] = screenshot_path
            
            # Check for shutdown before database operations
            if shutdown_check and shutdown_check():
                logger.info("Shutdown requested before database operations")
                return None, []
            
            # Insert domain data
            domain_id = self.db.insert_domain(domain_data)
            
            # Collect relationships and discover new URLs
            relationships, discovered_urls = self._collect_relationships_and_discover(domain_name, domain_id, shutdown_check)
            
            # Add discovered URLs to queue for future processing
            if discovered_urls:
                self.add_discovered_urls_to_queue(discovered_urls, depth + 1)
            
            processing_time = time.time() - start_time
            self.db.update_collection_log(
                domain_name, 'completed', 
                processing_time=processing_time,
                relationships_found=len(relationships),
                urls_discovered=len(discovered_urls),
                url=url,
                agent_name=COLLECTION_CONFIG['internal_agent_name']
            )
            
            logger.info(f"Successfully collected data for {domain_name} in {processing_time:.2f}s")
            logger.info(f"Found {len(relationships)} relationships and discovered {len(discovered_urls)} URLs for {domain_name}")
            return domain_id, relationships
            
        except Exception as e:
            processing_time = time.time() - start_time
            error_msg = str(e)
            logger.error(f"Error collecting data for {domain_name}: {error_msg}")
            self.db.update_collection_log(
                domain_name, 'failed', 
                error_message=error_msg,
                processing_time=processing_time,
                url=url,
                agent_name=COLLECTION_CONFIG['internal_agent_name']
            )
            raise
    
    def _collect_web_data(self, domain_name):
        """Collect basic web data (title, description, favicon)"""
        try:
            # Check if we're allowed to scrape this domain (root path)
            if not self._is_allowed_to_scrape(domain_name, '/'):
                logger.warning(f"Skipping {domain_name} - not allowed to scrape root path according to robots.txt")
                return {}
            
            url = f"http://{domain_name}"
            response = self.session.get(url, timeout=COLLECTION_CONFIG['timeout'])
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            data = {}
            
            # Get title
            title_tag = soup.find('title')
            data['title'] = title_tag.get_text().strip() if title_tag else None
            
            # Get description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if not meta_desc:
                meta_desc = soup.find('meta', attrs={'property': 'og:description'})
            data['description'] = meta_desc.get('content', '').strip() if meta_desc else None
            
            # Get favicon
            favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
            if favicon:
                favicon_url = favicon.get('href')
                # Ensure favicon_url is a string (not a list)
                if isinstance(favicon_url, list):
                    favicon_url = favicon_url[0] if favicon_url else None
                if favicon_url:
                    data['favicon_url'] = urljoin(url, favicon_url)
            
            return data
            
        except Exception as e:
            logger.warning(f"Error collecting web data for {domain_name}: {e}")
            return {}
    
    def _collect_whois_data(self, domain_name):
        """Collect WHOIS data"""
        try:
            # Use the correct API for the whois package
            w = whois.query(domain_name)
            
            data = {}
            
            # Handle creation date
            if w and w.creation_date:
                if isinstance(w.creation_date, list):
                    data['created_date'] = w.creation_date[0]
                else:
                    data['created_date'] = w.creation_date
            
            # Handle expiry date
            if w and w.expiration_date:
                if isinstance(w.expiration_date, list):
                    data['expiry_date'] = w.expiration_date[0]
                else:
                    data['expiry_date'] = w.expiration_date
            
            # Get registrar
            if w and w.registrar:
                data['registrar'] = w.registrar
            
            return data
            
        except Exception as e:
            logger.warning(f"Error collecting WHOIS data for {domain_name}: {e}")
            # Try fallback method
            return self._collect_whois_fallback(domain_name)
    
    def _collect_whois_fallback(self, domain_name):
        """Fallback WHOIS collection using socket connection"""
        try:
            import socket
            
            # Common WHOIS servers
            whois_servers = {
                '.com': 'whois.verisign-grs.com',
                '.net': 'whois.verisign-grs.com',
                '.org': 'whois.pir.org',
                '.info': 'whois.afilias.net',
                '.biz': 'whois.biz',
                '.co': 'whois.nic.co',
                '.io': 'whois.nic.io',
                '.me': 'whois.nic.me',
                '.tv': 'whois.nic.tv',
                '.cc': 'whois.nic.cc'
            }
            
            # Determine WHOIS server based on TLD
            tld = '.' + domain_name.split('.')[-1]
            whois_server = whois_servers.get(tld, 'whois.iana.org')
            
            # Connect to WHOIS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((whois_server, 43))
            
            # Send query
            query = domain_name + '\r\n'
            sock.send(query.encode())
            
            # Receive response
            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            # Parse response
            whois_text = response.decode('utf-8', errors='ignore')
            data = {}
            
            # Extract registrar
            registrar_patterns = [
                r'Registrar:\s*(.+)',
                r'Registrar Name:\s*(.+)',
                r'Sponsoring Registrar:\s*(.+)'
            ]
            
            for pattern in registrar_patterns:
                match = re.search(pattern, whois_text, re.IGNORECASE)
                if match:
                    data['registrar'] = match.group(1).strip()
                    break
            
            # Extract creation date
            creation_patterns = [
                r'Creation Date:\s*(.+)',
                r'Created:\s*(.+)',
                r'Created Date:\s*(.+)'
            ]
            
            for pattern in creation_patterns:
                match = re.search(pattern, whois_text, re.IGNORECASE)
                if match:
                    try:
                        date_val = match.group(1)
                        if isinstance(date_val, str):
                            date_str = date_val.strip()
                            # Try to parse various date formats
                            for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%d-%b-%Y']:
                                try:
                                    data['created_date'] = datetime.strptime(date_str, fmt).date()
                                    break
                                except ValueError:
                                    continue
                    except Exception:
                        pass
                    break
            
            # Extract expiry date
            expiry_patterns = [
                r'Registry Expiry Date:\s*(.+)',
                r'Expiration Date:\s*(.+)',
                r'Expires:\s*(.+)'
            ]
            
            for pattern in expiry_patterns:
                match = re.search(pattern, whois_text, re.IGNORECASE)
                if match:
                    try:
                        date_val = match.group(1)
                        if isinstance(date_val, str):
                            date_str = date_val.strip()
                            # Try to parse various date formats
                            for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%d-%b-%Y']:
                                try:
                                    data['expiry_date'] = datetime.strptime(date_str, fmt).date()
                                    break
                                except ValueError:
                                    continue
                    except Exception:
                        pass
                    break
            
            return data
            
        except Exception as e:
            logger.warning(f"Fallback WHOIS also failed for {domain_name}: {e}")
            return {}
    
    def _collect_dns_data(self, domain_name):
        """Collect DNS and ASN data"""
        try:
            data = {}
            
            # Get nameservers with better error handling
            try:
                # Try to get nameservers for the domain
                nameservers = dns.resolver.resolve(domain_name, 'NS')
                data['nameservers'] = json.dumps([str(ns) for ns in nameservers])
            except dns.resolver.NXDOMAIN:
                logger.warning(f"Domain {domain_name} does not exist")
                data['nameservers'] = None
            except dns.resolver.NoAnswer:
                logger.warning(f"No nameserver records found for {domain_name}")
                data['nameservers'] = None
            except dns.resolver.Timeout:
                logger.warning(f"DNS timeout for {domain_name}")
                data['nameservers'] = None
            except Exception as e:
                logger.warning(f"Error getting nameservers for {domain_name}: {e}")
                data['nameservers'] = None
            
            # Get ASN information
            try:
                # Get IP address first
                ip_address = socket.gethostbyname(domain_name)
                
                # Use external service to get ASN info
                asn_data = self._get_asn_info(ip_address)
                if asn_data:
                    data['asn'] = asn_data.get('asn')
                    data['asn_description'] = asn_data.get('description')
                
            except socket.gaierror:
                logger.warning(f"Could not resolve IP address for {domain_name}")
            except Exception as e:
                logger.warning(f"Error getting ASN data for {domain_name}: {e}")
            
            return data
            
        except Exception as e:
            logger.warning(f"Error collecting DNS data for {domain_name}: {e}")
            return {}
    
    def _get_asn_info(self, ip_address):
        """Get ASN information for an IP address"""
        try:
            # Using ipinfo.io API (free tier available)
            response = self.session.get(f"https://ipinfo.io/{ip_address}/json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'asn': data.get('org', '').split()[0] if data.get('org') else None,
                    'description': data.get('org')
                }
        except Exception as e:
            logger.warning(f"Error getting ASN info for {ip_address}: {e}")
        
        return None
    
    def _collect_ssl_data(self, domain_name):
        """Collect SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain_name, 443), timeout=COLLECTION_CONFIG['timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                    cert = ssock.getpeercert()
                    
                    data = {
                        'ssl_valid': True,
                        'ssl_expiry': None
                    }
                    
                    # Parse expiry date
                    if cert and 'notAfter' in cert:
                        expiry_str = cert['notAfter']
                        try:
                            data['ssl_expiry'] = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z').date()
                        except ValueError:
                            pass
                    
                    return data
                    
        except Exception as e:
            logger.warning(f"Error collecting SSL data for {domain_name}: {e}")
            return {'ssl_valid': False, 'ssl_expiry': None}
    
    def _collect_geolocation_data(self, domain_name):
        """Collect geolocation data using MaxMind, with ipinfo.io fallback if enabled. Nominatim is not used for IPs."""
        try:
            ip_address = socket.gethostbyname(domain_name)
            data = {'ip_address': ip_address}
            # Try MaxMind first
            if self.maxmind_reader:
                try:
                    response = self.maxmind_reader.city(ip_address)
                    data['latitude'] = response.location.latitude
                    data['longitude'] = response.location.longitude
                    data['country'] = response.country.iso_code
                    data['city'] = response.city.name
                    logger.info(f"MaxMind geolocation for {domain_name} ({ip_address}): {data}")
                    return data
                except Exception as e:
                    logger.warning(f'MaxMind lookup failed for {ip_address}: {e}')
            # Fallback to ipinfo if enabled
            if DATA_CONFIG.get('ipinfo_fallback', True):
                try:
                    url = f'https://ipinfo.io/{ip_address}/json'
                    token = DATA_CONFIG.get('ipinfo_token')
                    if token:
                        url += f'?token={token}'
                    resp = requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        info = resp.json()
                        loc = info.get('loc', '').split(',')
                        data['latitude'] = float(loc[0]) if len(loc) == 2 else None
                        data['longitude'] = float(loc[1]) if len(loc) == 2 else None
                        data['country'] = info.get('country')
                        data['city'] = info.get('city')
                        logger.info(f"ipinfo.io geolocation for {domain_name} ({ip_address}): {data}")
                        return data
                except Exception as e:
                    logger.warning(f'ipinfo.io lookup failed for {ip_address}: {e}')
            logger.warning(f'No geolocation found for {domain_name} ({ip_address})')
            return data
        except Exception as e:
            logger.warning(f'Error collecting geolocation data for {domain_name}: {e}')
            return {}
    
    def _take_screenshot(self, domain_name):
        """Take a screenshot of the domain"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.chrome.options import Options
            from webdriver_manager.chrome import ChromeDriverManager
            
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            try:
                driver.set_window_size(1920, 1080)
                driver.get(f"http://{domain_name}")
                time.sleep(3)  # Wait for page to load
                
                screenshot_path = os.path.join(
                    DATA_CONFIG['screenshot_dir'], 
                    f"{domain_name.replace('.', '_')}.png"
                )
                driver.save_screenshot(screenshot_path)
                
                return screenshot_path
                
            finally:
                driver.quit()
                
        except Exception as e:
            logger.warning(f"Error taking screenshot for {domain_name}: {e}")
            return None
    
    def _collect_relationships_and_discover(self, domain_name, source_domain_id, shutdown_check=None):
        """Collect relationships and discover new URLs for queue with comprehensive filtering and shutdown support"""
        relationships = []
        discovered_urls = []
        excluded_count = 0
        
        try:
            # Check for shutdown
            if shutdown_check and shutdown_check():
                logger.info("Shutdown requested during relationship collection")
                return relationships, discovered_urls
            
            # Check if we're allowed to scrape this domain
            if not self._is_allowed_to_scrape(domain_name):
                logger.warning(f"Skipping relationship collection for {domain_name} - not allowed to scrape according to robots.txt")
                return relationships, discovered_urls
            
            url = f"http://{domain_name}"
            
            # Don't skip relationship discovery even if URL was processed
            # We want to discover new relationships and URLs regardless
            
            response = self.session.get(url, timeout=COLLECTION_CONFIG['timeout'])
            response.raise_for_status()
            
            # Check for shutdown after network request
            if shutdown_check and shutdown_check():
                logger.info("Shutdown requested after network request")
                return relationships, discovered_urls
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find ALL links on the page
            all_links = soup.find_all('a', href=True)
            logger.info(f"Found {len(all_links)} total links on {domain_name}")
            
            # Step 1: Filter and categorize all links
            valid_internal_links = []
            valid_external_links = []
            
            for link in all_links:
                # Check for shutdown during link processing
                if shutdown_check and shutdown_check():
                    logger.info("Shutdown requested during link processing")
                    return relationships, discovered_urls
                
                href = link.get('href')
                link_text = link.get_text().strip()
                
                # Skip if no href
                if not href:
                    continue
                
                # Check if URL should be excluded
                should_exclude, reason = self._should_exclude_url(href, link_text)
                if should_exclude:
                    excluded_count += 1
                    continue
                
                # Parse the URL
                parsed_url = urlparse(href)
                target_domain = parsed_url.netloc.lower()
                
                # Skip if no netloc (relative links, javascript, etc.)
                if not target_domain:
                    continue
                
                # Clean domain (remove www. prefix)
                if target_domain.startswith('www.'):
                    target_domain = target_domain[4:]
                
                # Validate domain format
                if not self._is_valid_domain(target_domain):
                    continue
                
                # Categorize as internal or external
                if target_domain == domain_name:
                    valid_internal_links.append({
                        'href': href,
                        'link_text': link_text,
                        'domain': target_domain
                    })
                else:
                    valid_external_links.append({
                        'href': href,
                        'link_text': link_text,
                        'domain': target_domain
                    })
            
            logger.info(f"Valid internal links: {len(valid_internal_links)}")
            logger.info(f"Valid external links: {len(valid_external_links)}")
            
            # Check for shutdown before processing links
            if shutdown_check and shutdown_check():
                logger.info("Shutdown requested before processing links")
                return relationships, discovered_urls
            
            # Step 2: Calculate limits
            max_links = COLLECTION_CONFIG['max_links_per_page']
            max_internal_links = max(1, max_links // 4)  # 25% of max links for internal
            max_external_links = max_links - max_internal_links  # Remaining for external
            
            # Step 3: Add internal links (up to 25% of max)
            internal_links_added = 0
            unique_internal_urls = set()  # Track unique internal URLs, not domains
            
            for link_data in valid_internal_links:
                # Check for shutdown during internal link processing
                if shutdown_check and shutdown_check():
                    logger.info("Shutdown requested during internal link processing")
                    return relationships, discovered_urls
                
                if internal_links_added >= max_internal_links:
                    break
                
                href = link_data['href']
                link_text = link_data['link_text']
                target_domain = link_data['domain']
                
                # Clean URL for uniqueness check (remove parameters and fragments)
                clean_url = self._clean_url_for_queue(href)
                
                # Skip if we've already processed this internal URL
                if clean_url in unique_internal_urls:
                    continue
                unique_internal_urls.add(clean_url)
                
                # Check domain processing limit
                domain_processing_count = self.db.get_domain_processing_count(target_domain)
                if domain_processing_count >= COLLECTION_CONFIG['max_urls_per_domain']:
                    logger.info(f"Skipping internal {target_domain} - already processed {domain_processing_count} URLs")
                    continue
                
                # Get or create target domain ID
                target_domain_id = self.db.get_domain_id(target_domain)
                if not target_domain_id:
                    minimal_data = {'domain_name': target_domain}
                    target_domain_id = self.db.insert_domain(minimal_data)
                
                # --- Relationship Type Detection ---
                rel_type = 'link'
                ext_source = tldextract.extract(domain_name)
                ext_target = tldextract.extract(target_domain)
                # Subdomain: always mark as subdomain if source is parent of target
                if (
                    ext_source.domain == ext_target.domain and
                    ext_source.suffix == ext_target.suffix and
                    ext_source.subdomain == '' and ext_target.subdomain != ''
                ):
                    rel_type = 'subdomain'
                else:
                    # Redirect: only if HTTP status is 3xx, final domain is different, and not protocol-only
                    final_url = None
                    if not href.startswith('#') and not href.lower().startswith('mailto:'):
                        try:
                            resp = self.session.head(href, allow_redirects=True, timeout=COLLECTION_CONFIG['timeout'])
                            final_url = resp.url
                            status_code = resp.status_code
                            final_domain = urlparse(final_url).netloc.lower()
                            if final_domain.startswith('www.'):
                                final_domain = final_domain[4:]
                            # Ignore protocol-only redirects (http <-> https on same domain)
                            orig_url = urlparse(href)
                            orig_domain = orig_url.netloc.lower()
                            if orig_domain.startswith('www.'):
                                orig_domain = orig_domain[4:]
                            protocol_only = (final_domain == orig_domain and orig_url.scheme != urlparse(final_url).scheme)
                            if (
                                status_code >= 300 and status_code < 400 and
                                final_domain and final_domain != target_domain and
                                not protocol_only
                            ):
                                rel_type = 'redirect'
                                # Insert redirect relationship
                                final_domain_id = self.db.get_domain_id(final_domain)
                                if not final_domain_id:
                                    minimal_data = {'domain_name': final_domain}
                                    final_domain_id = self.db.insert_domain(minimal_data)
                                redirect_relationship = {
                                    'type': 'redirect',
                                    'link_text': link_text,
                                    'link_url': href
                                }
                                self.db.insert_relationship(source_domain_id, final_domain_id, redirect_relationship)
                                relationships.append({
                                    'source': domain_name,
                                    'target': final_domain,
                                    'type': 'redirect',
                                    'link_text': link_text,
                                    'link_url': href
                                })
                        except Exception as e:
                            logger.debug(f"Redirect check failed for {href}: {e}")
                # Insert main relationship
                relationship_data = {
                    'type': rel_type,
                    'link_text': link_text,
                    'link_url': href
                }
                self.db.insert_relationship(source_domain_id, target_domain_id, relationship_data)
                relationships.append({
                    'source': domain_name,
                    'target': target_domain,
                    'type': rel_type,
                    'link_text': link_text,
                    'link_url': href
                })
                
                # Add to discovery queue
                discovered_urls.append({
                    'url': clean_url,
                    'domain': target_domain,
                    'source_domain_id': source_domain_id
                })
                
                internal_links_added += 1
                logger.debug(f"Added internal link {internal_links_added}/{max_internal_links}: {clean_url}")
            
            # Check for shutdown before external link processing
            if shutdown_check and shutdown_check():
                logger.info("Shutdown requested before external link processing")
                return relationships, discovered_urls
            
            # Step 4: Add external links (remaining slots)
            external_links_added = 0
            unique_external_domains = set()  # For external, still count unique domains
            
            for link_data in valid_external_links:
                # Check for shutdown during external link processing
                if shutdown_check and shutdown_check():
                    logger.info("Shutdown requested during external link processing")
                    return relationships, discovered_urls
                
                if external_links_added >= max_external_links:
                    break
                
                href = link_data['href']
                link_text = link_data['link_text']
                target_domain = link_data['domain']
                
                # Skip if we've already processed this external domain
                if target_domain in unique_external_domains:
                    continue
                unique_external_domains.add(target_domain)
                
                # Check domain processing limit
                domain_processing_count = self.db.get_domain_processing_count(target_domain)
                if domain_processing_count >= COLLECTION_CONFIG['max_urls_per_domain']:
                    logger.info(f"Skipping external {target_domain} - already processed {domain_processing_count} URLs")
                    continue
                
                # Get or create target domain ID
                target_domain_id = self.db.get_domain_id(target_domain)
                if not target_domain_id:
                    minimal_data = {'domain_name': target_domain}
                    target_domain_id = self.db.insert_domain(minimal_data)
                
                # --- Relationship Type Detection ---
                rel_type = 'link'
                ext_source = tldextract.extract(domain_name)
                ext_target = tldextract.extract(target_domain)
                if (
                    ext_source.domain == ext_target.domain and
                    ext_source.suffix == ext_target.suffix and
                    ext_source.subdomain == '' and ext_target.subdomain != ''
                ):
                    rel_type = 'subdomain'
                else:
                    final_url = None
                    if not href.startswith('#') and not href.lower().startswith('mailto:'):
                        try:
                            resp = self.session.head(href, allow_redirects=True, timeout=COLLECTION_CONFIG['timeout'])
                            final_url = resp.url
                            status_code = resp.status_code
                            final_domain = urlparse(final_url).netloc.lower()
                            if final_domain.startswith('www.'):
                                final_domain = final_domain[4:]
                            orig_url = urlparse(href)
                            orig_domain = orig_url.netloc.lower()
                            if orig_domain.startswith('www.'):
                                orig_domain = orig_domain[4:]
                            protocol_only = (final_domain == orig_domain and orig_url.scheme != urlparse(final_url).scheme)
                            if (
                                status_code >= 300 and status_code < 400 and
                                final_domain and final_domain != target_domain and
                                not protocol_only
                            ):
                                rel_type = 'redirect'
                                final_domain_id = self.db.get_domain_id(final_domain)
                                if not final_domain_id:
                                    minimal_data = {'domain_name': final_domain}
                                    final_domain_id = self.db.insert_domain(minimal_data)
                                redirect_relationship = {
                                    'type': 'redirect',
                                    'link_text': link_text,
                                    'link_url': href
                                }
                                self.db.insert_relationship(source_domain_id, final_domain_id, redirect_relationship)
                                relationships.append({
                                    'source': domain_name,
                                    'target': final_domain,
                                    'type': 'redirect',
                                    'link_text': link_text,
                                    'link_url': href
                                })
                        except Exception as e:
                            logger.debug(f"Redirect check failed for {href}: {e}")
                relationship_data = {
                    'type': rel_type,
                    'link_text': link_text,
                    'link_url': href
                }
                self.db.insert_relationship(source_domain_id, target_domain_id, relationship_data)
                relationships.append({
                    'source': domain_name,
                    'target': target_domain,
                    'type': rel_type,
                    'link_text': link_text,
                    'link_url': href
                })
                clean_url = self._clean_url_for_queue(href)
                discovered_urls.append({
                    'url': clean_url,
                    'domain': target_domain,
                    'source_domain_id': source_domain_id
                })
                external_links_added += 1
                logger.debug(f"Added external link {external_links_added}/{max_external_links}: {target_domain}")
            
            # Record URL processing
            self.db.record_url_processing(url, domain_name, 'success', len(relationships))
            
            logger.info(f"Found {len(relationships)} relationships and discovered {len(discovered_urls)} URLs for {domain_name}")
            logger.info(f"Internal links added: {internal_links_added}/{max_internal_links}")
            logger.info(f"External links added: {external_links_added}/{max_external_links}")
            if excluded_count > 0:
                logger.info(f"Excluded {excluded_count} URLs due to filtering rules")
            
        except Exception as e:
            logger.warning(f"Error collecting relationships for {domain_name}: {e}")
            # Record failed processing
            self.db.record_url_processing(url, domain_name, 'failed', 0)
        
        return relationships, discovered_urls
    
    def _is_valid_domain(self, domain):
        """Check if domain is valid"""
        if not domain:
            return False
        
        # Basic domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, domain))
    
    def add_discovered_urls_to_queue(self, discovered_urls, depth=1):
        """Add discovered URLs to the queue for future processing with duplicate prevention"""
        added_count = 0
        skipped_count = 0
        
        for url_data in discovered_urls:
            try:
                url = url_data['url']
                domain_name = url_data['domain']
                
                # Check if URL is already in the queue (better than checking if processed)
                if self.db.is_url_in_queue(url):
                    skipped_count += 1
                    continue
                
                # Check domain processing limit
                domain_processing_count = self.db.get_domain_processing_count(domain_name)
                if domain_processing_count >= COLLECTION_CONFIG['max_urls_per_domain']:
                    skipped_count += 1
                    continue
                
                self.db.add_to_discovery_queue(
                    url=url,
                    domain_name=domain_name,
                    source_domain_id=url_data.get('source_domain_id'),
                    depth=depth,
                    priority=1
                )
                added_count += 1
                
            except Exception as e:
                logger.warning(f"Error adding URL to queue: {e}")
                skipped_count += 1
        
        logger.info(f"Added {added_count} URLs to queue, skipped {skipped_count} duplicates/limits")
    
    def process_queue(self, max_items=50, max_depth=3, shutdown_check=None):
        """Process URLs from the discovery queue with enhanced safeguards and shutdown support"""
        logger.info("Starting queue processing...")
        
        try:
            while True:
                # Check for shutdown
                if shutdown_check and shutdown_check():
                    logger.info("Shutdown requested, stopping queue processing")
                    break
                
                # Get next batch from queue
                queue_items = self.db.get_next_from_queue(limit=max_items)
                
                if not queue_items:
                    logger.info("Queue is empty, stopping processing")
                    break
                
                logger.info(f"Processing {len(queue_items)} items from queue")
                
                for item in queue_items:
                    # Check for shutdown before each item
                    if shutdown_check and shutdown_check():
                        logger.info("Shutdown requested, stopping queue processing")
                        return
                    
                    try:
                        domain_name = item['domain_name']
                        depth = item['depth']
                        url = item['url']
                        
                        # Skip if we've reached max depth
                        if depth >= max_depth:
                            logger.info(f"Skipping {domain_name} - reached max depth")
                            self.db.mark_queue_item_completed(item['id'], success=False, error_message="Max depth reached")
                            continue
                        
                        # Check if URL is already in queue (better than checking if processed)
                        if self.db.is_url_in_queue(url, exclude_id=item['id']):
                            logger.info(f"URL {url} already in queue, skipping")
                            self.db.mark_queue_item_completed(item['id'], success=False, error_message="Already in queue")
                            continue
                        
                        # Check domain processing limit
                        domain_processing_count = self.db.get_domain_processing_count(domain_name)
                        if domain_processing_count >= COLLECTION_CONFIG['max_urls_per_domain']:
                            logger.info(f"Skipping {domain_name} - reached processing limit ({domain_processing_count})")
                            self.db.mark_queue_item_completed(item['id'], success=False, error_message="Domain processing limit reached")
                            continue
                        
                        # Collect domain data
                        domain_id, relationships = self.collect_domain_data(domain_name, depth, url, shutdown_check)
                        
                        # Mark as completed
                        self.db.mark_queue_item_completed(item['id'], success=True)
                        
                        # Respect rate limiting
                        time.sleep(COLLECTION_CONFIG['request_delay'])
                        
                    except Exception as e:
                        logger.error(f"Error processing queue item {item['id']}: {e}")
                        self.db.mark_queue_item_completed(item['id'], success=False, error_message=str(e))
                        
        except KeyboardInterrupt:
            logger.info("Queue processing interrupted by user")
            # Mark any remaining processing items as failed
            try:
                cursor = self.db.connection.cursor()
                cursor.execute("""
                    UPDATE discovery_queue 
                    SET status = 'failed', error_message = 'Processing interrupted'
                    WHERE status = 'processing'
                """)
                self.db.connection.commit()
                cursor.close()
                logger.info("Marked interrupted queue items as failed")
            except Exception as e:
                logger.error(f"Error marking interrupted items: {e}")
        except Exception as e:
            logger.error(f"Queue processing failed: {e}")
    
    def crawl_from_seed_domains(self, seed_domains, max_depth=2):
        """Crawl domains starting from seed domains"""
        visited = set()
        to_visit = [(domain, 0) for domain in seed_domains]  # (domain, depth)
        
        while to_visit:
            domain, depth = to_visit.pop(0)
            
            if domain in visited or depth > max_depth:
                continue
            
            visited.add(domain)
            
            try:
                logger.info(f"Crawling {domain} at depth {depth}")
                domain_id, relationships = self.collect_domain_data(domain, depth)
                
                # Add new domains to visit if not at max depth
                if depth < max_depth:
                    for rel in relationships:
                        target_domain = rel['target']
                        if target_domain not in visited:
                            to_visit.append((target_domain, depth + 1))
                
                # Respect rate limiting
                time.sleep(COLLECTION_CONFIG['request_delay'])
                
            except Exception as e:
                logger.error(f"Error crawling {domain}: {e}")
    
    def close(self):
        """Clean up resources"""
        self.db.close()
        self.session.close()

    def _parse_robots_txt(self, content):
        """Parse robots.txt into a dict of user-agent -> list of (type, value) rules."""
        rules = {}
        current_agents = []
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' not in line:
                continue
            directive, value = line.split(':', 1)
            directive = directive.strip().lower()
            value = value.strip()
            if directive == 'user-agent':
                agent = value.lower()
                current_agents.append(agent)
                if agent not in rules:
                    rules[agent] = []
            elif directive in ('disallow', 'allow'):
                for agent in current_agents:
                    rules.setdefault(agent, []).append((directive, value))
            else:
                # Any other directive resets the agent list (new section)
                current_agents = []
        return rules

    def _path_matches(self, path, rule_value):
        """Check if a path matches a robots.txt rule value."""
        if not rule_value:
            return True  # Empty rule matches everything
        if not rule_value.startswith('/'):
            rule_value = '/' + rule_value
        # Simple prefix matching
        return path.startswith(rule_value)

    def _find_robots_decision(self, path, rules):
        """Apply longest-match-wins logic for Allow/Disallow rules."""
        # Normalize path
        if not path.startswith('/'):
            path = '/' + path
        matched = None
        matched_type = None
        matched_value = None
        max_len = -1
        for rule_type, rule_value in rules:
            if not rule_value:
                rule_value = '/'  # Disallow: (empty) means block all
            if self._path_matches(path, rule_value):
                if len(rule_value) > max_len:
                    matched = rule_type
                    matched_type = rule_type
                    matched_value = rule_value
                    max_len = len(rule_value)
        # If no match, allowed
        if matched is None:
            return True, 'none', ''
        # If both Allow and Disallow match, Allow wins if it's the longest
        if matched_type == 'allow':
            return True, matched_type, matched_value
        else:
            return False, matched_type, matched_value

    def _check_robots_txt(self, domain_name, path='/'):
        """Check robots.txt to see if we're allowed to scrape a specific path on this domain, with proper user-agent and rule precedence handling."""
        if not COLLECTION_CONFIG.get('respect_robots_txt', True):
            logger.debug(f"Robots.txt checking disabled for {domain_name}")
            return True
        try:
            robots_url = f"http://{domain_name}/robots.txt"
            response = self.session.get(robots_url, timeout=COLLECTION_CONFIG['timeout'])
            if response.status_code != 200:
                logger.info(f"Robots.txt not found for {domain_name} (status: {response.status_code})")
                return True
            robots_content = response.text
            logger.debug(f"Robots.txt content for {domain_name}:\n{robots_content}")
            # Parse robots.txt into user-agent sections
            rules = self._parse_robots_txt(robots_content)
            # Find the best matching user-agent section
            ua = COLLECTION_CONFIG['http_user_agent']
            matched_rules = rules.get(ua, []) + rules.get('*', [])
            # Find the most specific rule for the path
            decision, rule_type, rule_value = self._find_robots_decision(path, matched_rules)
            if decision is False:
                logger.warning(f"Robots.txt for {domain_name} blocks path {path} due to {rule_type}: {rule_value}")
            else:
                logger.info(f"Robots.txt for {domain_name} allows path {path} (matched {rule_type}: {rule_value})")
            return decision
        except Exception as e:
            logger.warning(f"Error checking robots.txt for {domain_name}: {e}")
            return True


def main():
    """Main function to run the domain collector"""
    # Start auto-update checker
    auto_updater = AutoUpdate(AUTO_UPDATE_CONFIG, __version__, default_restart_callback)
    auto_updater.start_periodic_check()

    collector = DomainCollector()
    
    try:
        # Example seed domains
        seed_domains = [
            'blog.theravenhub.com'
        ]
        
        logger.info("Starting domain collection...")
        collector.crawl_from_seed_domains(seed_domains, max_depth=2)
        logger.info("Domain collection completed!")
        
    except KeyboardInterrupt:
        logger.info("Collection interrupted by user")
    except Exception as e:
        logger.error(f"Collection failed: {e}")
    finally:
        collector.close()


if __name__ == "__main__":
    main()