# config.py
import os

# File paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(BASE_DIR, 'cache_dir')
PICKLES_DIR = os.path.join(CACHE_DIR, 'pickles')
MODEL_FILE = os.path.join(PICKLES_DIR, 'model.joblib')
TRAINING_DATA_FILE = os.path.join(PICKLES_DIR, 'training_data.pkl')
FAILED_REQUESTS_FILE = os.path.join(PICKLES_DIR, 'failed_requests.pkl')

# Model parameters
MIN_TRAINING_SAMPLES = 100  # Minimum number of samples required for training
MAX_RECORDS = 10000        # Maximum number of records to keep in the training dataset
RETRAIN_INTERVAL = 100     # Number of requests between model retraining
NUM_RETRIES = 10     # Number of requests between model retraining
# Cache parameters
CACHE_EXPIRY_HOURS = 24    # Expiry time for cache files in hours
MAX_CACHE_SIZE_MB = 10000   # Maximum cache size in MB

# Ensure directories exist
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(PICKLES_DIR, exist_ok=True)