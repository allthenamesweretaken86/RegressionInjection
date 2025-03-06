# retry_manager.py

# retry_manager.py
import time
import logging
import random
import pandas as pd
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from model import ModelManager
from config import NUM_RETRIES
logger = logging.getLogger(__name__)

@dataclass
class RetryRequest:
    """Data class for retry request information"""
    flow_id: str
    url: str
    method: str
    headers: Dict
    content: Optional[bytes]
    attempt_count: int
    next_retry_time: float
    last_error: Optional[str] = None
    optimization_attempts: int = 0
    optimized_features: Dict = None

class RetryManager:
    def __init__(self, max_retries: int = NUM_RETRIES, initial_delay: int = 5):
        """Initialize the retry manager"""
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.retry_queue: Dict[str, RetryRequest] = {}
        self.model_manager = ModelManager()
        logger.info("RetryManager initialized")

    def optimize_request_features(self, retry_request: RetryRequest) -> Dict:
        """Generate optimized features for retry attempt"""
        try:
            # Get successful request patterns from model
            patterns = self.model_manager.get_successful_patterns()
            
            # Use default optimizations if no patterns available
            if patterns is None or patterns.empty:
                logger.info("Using default optimizations (no patterns available)")
                return self._get_default_optimizations(retry_request)

            # Select optimization strategy based on attempt count
            if retry_request.optimization_attempts == 0:
                try:
                    # First attempt: Use most successful pattern
                    pattern_dict = patterns.iloc[0].to_dict()
                    # Clean the pattern dictionary
                    optimized = {k: str(v) for k, v in pattern_dict.items() if v is not None}
                    logger.info("Using most successful pattern")
                except Exception as e:
                    logger.error(f"Error using most successful pattern: {e}")
                    return self._get_default_optimizations(retry_request)
            else:
                # Subsequent attempts: Try different patterns or variations
                optimized = self._generate_variant_features(patterns, retry_request)
                logger.info(f"Generated variant features for attempt {retry_request.optimization_attempts}")

            # Update optimization attempt counter
            retry_request.optimization_attempts += 1
            
            return optimized

        except Exception as e:
            logger.error(f"Error optimizing request features: {e}", exc_info=True)
            return self._get_default_optimizations(retry_request)

    def _generate_variant_features(self, patterns: pd.DataFrame, retry_request: RetryRequest) -> Dict:
        """Generate variant features based on successful patterns"""
        try:
            # Features we can safely modify
            mutable_features = [
                'user_agent',
                'accept_language',
                'accept_encoding',
                'cache_control',
                'connection'
            ]

            # Base features from current request
            variant = retry_request.headers.copy()

            # Select a random successful pattern
            pattern = patterns.sample(n=1).iloc[0]

            # Randomly select features to modify
            num_features_to_modify = random.randint(1, len(mutable_features))
            features_to_modify = random.sample(mutable_features, num_features_to_modify)

            # Apply modifications
            for feature in features_to_modify:
                if feature in pattern and pattern[feature] is not None:
                    variant[feature] = pattern[feature]

            return variant

        except Exception as e:
            logger.error(f"Error generating variant features: {e}")
            return retry_request.headers.copy()

    def _get_default_optimizations(self, retry_request: RetryRequest) -> Dict:
        """Get default optimization features when no patterns are available"""
        default_optimizations = {
            'User-Agent': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
            ],
            'Accept-Language': ['en-US,en;q=0.9', 'en-GB,en;q=0.8'],
            'Accept-Encoding': ['gzip, deflate, br', 'gzip, deflate'],
            'Cache-Control': ['no-cache', 'max-age=0'],
            'Connection': ['keep-alive', 'close']
        }

        # Create variant based on attempt number
        variant = retry_request.headers.copy()
        attempt = retry_request.optimization_attempts

        for header, values in default_optimizations.items():
            variant[header] = values[attempt % len(values)]

        return variant

    def add_failed_request(self, flow) -> None:
        """Add a failed request to the retry queue"""
        try:
            # Skip if request is already in retry queue
            if flow.id in self.retry_queue:
                return

            retry_request = RetryRequest(
                flow_id=flow.id,
                url=flow.request.url,
                method=flow.request.method,
                headers=dict(flow.request.headers),
                content=flow.request.content,
                attempt_count=0,
                next_retry_time=self._calculate_next_retry_time(0)
            )
            
            # Generate optimized features for first attempt
            retry_request.optimized_features = self.optimize_request_features(retry_request)
            
            self.retry_queue[flow.id] = retry_request
            logger.info(f"Added request to retry queue: {flow.request.url}")
            
        except Exception as e:
            logger.error(f"Error adding request to retry queue: {e}")

    def update_retry_status(self, flow_id: str, success: bool, error: Optional[str] = None) -> None:
        """Update the status of a retry attempt and optimize if needed"""
        try:
            if flow_id not in self.retry_queue:
                return

            retry_request = self.retry_queue[flow_id]
            
            if success:
                # If successful, record the successful features
                self.model_manager.record_successful_features(
                    retry_request.optimized_features
                )
                del self.retry_queue[flow_id]
                logger.info(f"Successful retry for request: {flow_id}")
            else:
                retry_request.attempt_count += 1
                retry_request.last_error = error

                if retry_request.attempt_count < self.max_retries:
                    # Generate new optimized features for next attempt
                    retry_request.optimized_features = self.optimize_request_features(
                        retry_request
                    )
                    retry_request.next_retry_time = self._calculate_next_retry_time(
                        retry_request.attempt_count
                    )
                    logger.warning(
                        f"Failed retry attempt {retry_request.attempt_count} for request: {flow_id}. "
                        f"Next attempt with optimized features."
                    )
                else:
                    del self.retry_queue[flow_id]
                    logger.warning(f"Max retries reached for request: {flow_id}")

        except Exception as e:
            logger.error(f"Error updating retry status: {e}")

    def _calculate_next_retry_time(self, attempt_count: int) -> float:
        """Calculate next retry time using exponential backoff"""
        delay = self.initial_delay * (2 ** attempt_count)  # Exponential backoff
        return time.time() + delay

    def get_ready_retries(self) -> List[RetryRequest]:
        """Get list of requests ready for retry with optimized features"""
        try:
            current_time = time.time()
            ready_retries = []
            expired_retries = []

            for flow_id, retry_request in self.retry_queue.items():
                if retry_request.attempt_count >= self.max_retries:
                    expired_retries.append(flow_id)
                    continue

                if current_time >= retry_request.next_retry_time:
                    if not retry_request.optimized_features:
                        retry_request.optimized_features = self.optimize_request_features(
                            retry_request
                        )
                    ready_retries.append(retry_request)

            # Clean up expired retries
            for flow_id in expired_retries:
                del self.retry_queue[flow_id]
                logger.info(f"Removed expired retry request: {flow_id}")

            return ready_retries

        except Exception as e:
            logger.error(f"Error getting ready retries: {e}")
            return []