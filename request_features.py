# request_features.py
import os
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, Tuple, List # Ensure List is imported
import logging
from dataclasses import dataclass, asdict, fields, MISSING
from config import (
    TRAINING_DATA_FILE, MAX_RECORDS, RETRAIN_INTERVAL, MIN_TRAINING_SAMPLES,
    RATING_SCALE_MIN, RATING_SCALE_MAX
)

logger = logging.getLogger(__name__)

@dataclass
class RequestFeatures:
    """
    Data class for request and response features for model training.
    Fields without default values MUST come before fields with default values.
    """
    # Fields without default values (Mandatory at instantiation time from mitmproxy flow)
    url: str
    timestamp: float # Request start time (Unix timestamp)
    request_method: str
    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str
    connection: str
    host: str
    origin: str
    referer: str
    cache_control: str
    content_type: str # Request's Content-Type header
    cookies: str # String representation of request cookies
    sec_fetch_dest: str
    sec_fetch_mode: str
    sec_fetch_site: str
    public_ip: str # Client's public IP address
    time_since_last_request: float # Seconds, or current_time if first request
    tls_fingerprint: str # Information about the TLS connection
    http_version: str # e.g., "HTTP/1.1", "HTTP/2"
    x_custom_headers: str # JSON string of key-value pairs

    # Fields with default values (Optional or populated later)
    request_content_length: Optional[int] = None # Content-Length of the request body

    # Response related features (populated after response is received, hence optional/defaulted)
    response_code: Optional[int] = None
    response_time_ms: Optional[float] = None # Duration in milliseconds
    
    html_length: Optional[int] = None # Raw length of HTML content from response
    html_length_score: Optional[float] = None # Score derived from html_length (e.g., 0-2)
    dominant_html_keyword_score: Optional[float] = None # Direct score (0-10) from a dominant keyword, or NaN

    rating: Optional[float] = None # Overall rating (target variable, 0-10 scale)


class RequestFeaturesModel:
    """Manages the collection, storage, and preparation of training data."""
    def __init__(self):
        self.request_count_since_last_train = 0
        self.training_df = self._load_or_initialize_dataframe(TRAINING_DATA_FILE)
        logger.info(f"RequestFeaturesModel initialized. Training data has {len(self.training_df)} records.")

    def _get_expected_columns(self) -> List[str]:
        """Defines the columns for the training DataFrame based on RequestFeatures dataclass fields."""
        return [f.name for f in fields(RequestFeatures)]

    def _load_or_initialize_dataframe(self, file_path: str) -> pd.DataFrame:
        """Initializes or loads the training DataFrame from a pickle file."""
        expected_columns = self._get_expected_columns()
        if os.path.exists(file_path):
            try:
                df = pd.read_pickle(file_path)
                current_cols_set = set(df.columns)
                expected_cols_set = set(expected_columns)

                for col_name in expected_cols_set - current_cols_set:
                    df[col_name] = pd.NA 
                
                cols_to_remove = list(current_cols_set - expected_cols_set)
                if cols_to_remove:
                    df = df.drop(columns=cols_to_remove)
                    logger.info(f"Removed obsolete columns from loaded training data: {cols_to_remove}")
                
                df = df[expected_columns]
                
                logger.info(f"Loaded training DataFrame from {file_path}, shape {df.shape}. Columns: {df.columns.tolist()}")
                return df
            except Exception as e:
                logger.error(f"Error loading or reconciling DataFrame from {file_path}: {e}. Initializing new one.", exc_info=True)
        
        logger.info(f"Initializing new training DataFrame for {file_path} with columns: {expected_columns}")
        return pd.DataFrame(columns=expected_columns)

    def add_request_response_pair(self, features_instance: RequestFeatures, model_manager) -> None:
        """
        Adds a new request-response data point to the training set.
        Triggers model retraining based on configured intervals and data size.
        """
        try:
            new_data_dict = asdict(features_instance)
            new_data_row = pd.DataFrame([new_data_dict], columns=self._get_expected_columns())

            self.training_df = pd.concat([self.training_df, new_data_row], ignore_index=True)
            
            if len(self.training_df) > MAX_RECORDS:
                self.training_df = self.training_df.iloc[-MAX_RECORDS:]
            
            self._save_dataframe(self.training_df, TRAINING_DATA_FILE)
            logger.info(f"Added new data point. Training data size: {len(self.training_df)}")

            self.request_count_since_last_train += 1
            if self.request_count_since_last_train >= RETRAIN_INTERVAL and len(self.training_df) >= MIN_TRAINING_SAMPLES:
                logger.info(f"Retrain interval ({RETRAIN_INTERVAL}) reached with sufficient samples ({len(self.training_df)}). Triggering model training...")
                metrics = model_manager.train(self.training_df.copy()) 
                if metrics:
                    logger.info(f"Model retraining completed. Metrics: {metrics}")
                else:
                    logger.warning("Model retraining was skipped or failed.")
                self.request_count_since_last_train = 0 
            elif len(self.training_df) < MIN_TRAINING_SAMPLES:
                 logger.debug(f"Not enough samples for retraining. Have {len(self.training_df)}, need {MIN_TRAINING_SAMPLES}. Request count since last train: {self.request_count_since_last_train}")

        except Exception as e:
            logger.error(f"Error adding request-response pair to training data: {e}", exc_info=True)

    def _save_dataframe(self, df: pd.DataFrame, file_path: str) -> None:
        """Saves the DataFrame to a pickle file, ensuring directory exists."""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            df.to_pickle(file_path)
            logger.debug(f"Training DataFrame successfully saved to {file_path}")
        except Exception as e:
            logger.error(f"Error saving training DataFrame to {file_path}: {e}", exc_info=True)

    def get_training_data_for_model(self) -> pd.DataFrame:
        """Provides a copy of the current training data for the ModelManager."""
        return self.training_df.copy()
