# utils.py:
# utils.py
import time
import pandas as pd
from typing import Dict, Union
import logging
from config import TRAINING_DATA_FILE
import os

logger = logging.getLogger(__name__)

def calculate_time_since_last_request(url: str) -> float:
    """
    Calculate time since the last request to this URL using the training data.
    
    Args:
        url (str): The URL to check
        
    Returns:
        float: Time in seconds since the last request to this URL.
               Returns current time if no previous requests found.
    """
    try:
        current_time = time.time()
        
        # Check if training data exists
        if not os.path.exists(TRAINING_DATA_FILE):
            return current_time
        
        # Load the DataFrame
        df = pd.read_pickle(TRAINING_DATA_FILE)
        
        # If DataFrame is empty or has no timestamps
        if df.empty or 'timestamp' not in df.columns:
            return current_time
            
        # Filter for the specific URL and get the latest timestamp
        url_requests = df[df['url'] == url]
        
        if url_requests.empty:
            return current_time
            
        latest_request_time = url_requests['timestamp'].max()
        
        # Calculate time difference
        time_diff = current_time - latest_request_time
        
        logger.debug(f"Time since last request to {url}: {time_diff:.2f} seconds")
        
        return time_diff
        
    except Exception as e:
        logger.error(f"Error calculating time since last request: {e}", exc_info=True)
        return current_time  # Return current time in case of any error

def rate_response(status_code: Union[int, Dict]) -> int:
    """Rate the response based on status code"""
    # Handle both int and dict input
    if isinstance(status_code, dict):
        status_code = status_code.get('status_code', 0)
    elif isinstance(status_code, int):
        pass
    else:
        return 0

    if 200 <= status_code < 300:
        return 1  # Success
    elif 300 <= status_code < 400:
        return 2  # Redirect
    elif 400 <= status_code < 500:
        return 3  # Client Error
    elif 500 <= status_code < 600:
        return 4  # Server Error
    else:
        return 0  # Unknown

def convert_bytes_to_str(value: Union[bytes, str, None]) -> str:
    """Convert bytes to string, handling None values"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)