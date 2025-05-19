# config.py
import os
import json
import logging

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(BASE_DIR, 'cache_dir')
PICKLES_DIR = os.path.join(CACHE_DIR, 'pickles') # Centralized pickles
MODEL_FILE = os.path.join(PICKLES_DIR, 'decision_tree_regressor_model.joblib') # More specific name
TRAINING_DATA_FILE = os.path.join(PICKLES_DIR, 'training_data_v2.pkl') # Versioning data file
# FAILED_REQUESTS_FILE = os.path.join(PICKLES_DIR, 'failed_requests.pkl') # Currently not central to core logic, can be re-added if needed by a specific module
HTML_RATING_KEYWORDS_FILE = os.path.join(PICKLES_DIR, 'html_rating_keywords_v2.json') # Versioned
LOG_FILE = os.path.join(BASE_DIR, 'proxy_system.log') # General log file for the system

DNS_BLOCKLIST_URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt"
LOCAL_DNS_BLOCKLIST_FILE = os.path.join(PICKLES_DIR, 'dns_blocklist.txt')

# Mitmproxy specific configurations
MITMPROXY_MAIN_SCRIPT = os.path.join(BASE_DIR, 'main.py')
MITMPROXY_CERT_DIR = os.path.join(BASE_DIR, 'mitmproxy_certs')
MITMPROXY_CA_CERT_FILENAME = "mitmproxy-ca-cert.pem"

MITMPROXY_LISTEN_HOST = '127.0.0.1'
MITMPROXY_LISTEN_PORT = 8081

# Model parameters
MIN_TRAINING_SAMPLES = 30 # Lowered for easier initial experimentation with new rating
MAX_RECORDS = 10000
RETRAIN_INTERVAL = 50 # Retrain after every 50 new data points added
NUM_RETRIES = 5 # Max retries for a failed request by RetryManager

# Cache parameters (for custom cache in cache.py)
# CACHE_DIR is already defined above
CACHE_EXPIRY_HOURS = 24
MAX_CACHE_SIZE_MB = 500 # Adjusted max cache size

# Management UI
MANAGEMENT_SERVER_HOST = '127.0.0.1'
MANAGEMENT_SERVER_PORT = 8000

# Rating System
RATING_SCALE_MIN = 0.0
RATING_SCALE_MAX = 10.0
RETRY_THRESHOLD_RATING = 4.0 # If rating is below this, consider for retry

# Ensure directories exist
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(PICKLES_DIR, exist_ok=True)
# MITMPROXY_CERT_DIR is expected to be created by mitmproxy or user setup

# Initialize HTML rating keywords file if it doesn't exist with new 0-10 scale in mind
# These are now direct scores/strong biases, not just small adjustments.
if not os.path.exists(HTML_RATING_KEYWORDS_FILE):
    os.makedirs(os.path.dirname(HTML_RATING_KEYWORDS_FILE), exist_ok=True) # Ensure dir exists
    default_html_keywords = {
        "captcha": 0.5,  # Very low score if captcha is detected
        "verify you are human": 0.5,
        "login required": 2.0, # Low score, page is not the target content
        "please log in": 2.0,
        "access denied": 1.0,
        "error": 1.5,
        "page not found": 1.0,
        "payment required": 2.5,
        "session expired": 2.0,
        # Positive keywords might be harder to define universally to set a high score
        # It's often the *absence* of negative keywords + good status + good content length
        # that implies success.
        # "welcome user": 9.0, # Example of a very positive indicator
        # "dashboard overview": 8.5,
        "success": 7.0 # Generic success message might not be the final page
    }
    try:
        with open(HTML_RATING_KEYWORDS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_html_keywords, f, indent=4)
        logging.info(f"Created default HTML rating keywords (0-10 scale) at {HTML_RATING_KEYWORDS_FILE}")
    except Exception as e:
        logging.error(f"Could not save default HTML keywords to {HTML_RATING_KEYWORDS_FILE}: {e}")