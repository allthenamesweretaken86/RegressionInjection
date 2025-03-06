# request_features.py: 
import os
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, Tuple
from utils import convert_bytes_to_str
import logging
from dataclasses import dataclass, asdict, fields, MISSING
from model import ModelManager
from config import (
    CACHE_DIR, FAILED_REQUESTS_FILE, MODEL_FILE, 
    TRAINING_DATA_FILE, MAX_RECORDS, RETRAIN_INTERVAL, MIN_TRAINING_SAMPLES
)

logger = logging.getLogger(__name__)

@dataclass
class RequestFeatures:
    """Data class for request features"""
    url: str
    timestamp: float
    user_agent: str
    public_ip: str
    time_since_last_request: float
    referrer: str
    accept_language: str
    accept_encoding: str
    origin: str
    content_type: str
    x_requested_with: str
    connection: str
    cookies: str
    x_forwarded_for: str
    tls_fingerprint: str
    http_version: str
    request_method: str
    cache_control: str
    x_custom_headers: str
    response_code: Optional[int] = None
    response_time: Optional[float] = None
    rating: Optional[int] = None

class RequestFeaturesModel:
    def __init__(self):
        self.model_manager = ModelManager()
        self.request_count = 0
        self.last_request_times = {}
        self.failed_requests_df = pd.DataFrame()
        self._initialize_dataframes()
        logger.info("RequestFeaturesModel initialized")
    def _save_and_retrain(self) -> None:
        """Save current data and retrain the model"""
        try:
            # Save the current data
            if not self.model_df.empty:
                self.model_df.to_pickle(TRAINING_DATA_FILE)
                logger.info("Training data saved successfully")

            # Retrain if we have enough data
            if len(self.model_df) >= MIN_TRAINING_SAMPLES:
                metrics = self.model_manager.train(self.model_df)
                if metrics:
                    logger.info(f"Model retrained successfully. Metrics: {metrics}")
                else:
                    logger.warning("Model retraining failed or insufficient data")
            else:
                logger.debug(f"Not enough samples for retraining. Current: {len(self.model_df)}")

        except Exception as e:
            logger.error(f"Error in save and retrain: {e}", exc_info=True)


    def update_model(self, features: Dict[str, Any]) -> None:
        """Update the model with new request features"""
        try:
            # Log incoming features for debugging
            logger.debug(f"Received features type: {type(features)}")
            logger.debug(f"Received features content: {features}")

            # Validate and prepare features
            prepared_features = self._prepare_features(features)
            
            # Convert to DataFrame row
            new_data = pd.DataFrame([asdict(prepared_features)])
            
            # Ensure all bytes are converted to strings
            for column in new_data.columns:
                if new_data[column].dtype == object:
                    new_data[column] = new_data[column].apply(
                        lambda x: x.decode() if isinstance(x, bytes) else str(x) if x is not None else None
                    )

            # Validate data types match RequestFeatures
            self._validate_datatypes(new_data)

            # Add new data to the model DataFrame
            self.model_df = pd.concat([self.model_df, new_data], ignore_index=True)
            
            # Trim if exceeds max records
            if len(self.model_df) > MAX_RECORDS:
                self.model_df = self.model_df.iloc[-MAX_RECORDS:]

            # Log success
            logger.info("Model updated with new request features")
            
            # Save and retrain if needed
            self.request_count += 1
            if self.request_count % RETRAIN_INTERVAL == 0:
                self._save_and_retrain()
            else:
                # Just save the data
                self.model_df.to_pickle(TRAINING_DATA_FILE)

        except Exception as e:
            logger.error(f"Error updating model: {e}", exc_info=True)
            raise
    def _initialize_dataframes(self) -> None:
        """Initialize or load existing dataframes"""
        try:
            # Define expected columns based on RequestFeatures fields
            expected_columns = list(RequestFeatures.__annotations__.keys())
            
            if os.path.exists(TRAINING_DATA_FILE):
                self.model_df = pd.read_pickle(TRAINING_DATA_FILE)
                # Validate columns match expected
                missing_cols = set(expected_columns) - set(self.model_df.columns)
                if missing_cols:
                    logger.warning(f"Adding missing columns to model_df: {missing_cols}")
                    for col in missing_cols:
                        self.model_df[col] = None
            else:
                self.model_df = pd.DataFrame(columns=expected_columns)

            if os.path.exists(FAILED_REQUESTS_FILE):
                self.failed_requests_df = pd.read_pickle(FAILED_REQUESTS_FILE)
                # Validate columns match expected
                missing_cols = set(expected_columns) - set(self.failed_requests_df.columns)
                if missing_cols:
                    logger.warning(f"Adding missing columns to failed_requests_df: {missing_cols}")
                    for col in missing_cols:
                        self.failed_requests_df[col] = None
            else:
                self.failed_requests_df = pd.DataFrame(columns=expected_columns)

        except Exception as e:
            logger.error(f"Error initializing dataframes: {e}", exc_info=True)
            self.model_df = pd.DataFrame(columns=expected_columns)
            self.failed_requests_df = pd.DataFrame(columns=expected_columns)
    

    def _prepare_features(self, features: Dict[str, Any]) -> RequestFeatures:
        """Prepare and validate features"""
        try:
            if isinstance(features, RequestFeatures):
                return features
                
            if not isinstance(features, dict):
                raise TypeError(f"Features must be dict or RequestFeatures, got {type(features)}")

            # Ensure all required fields are present
            required_fields = {f.name for f in fields(RequestFeatures) 
                             if f.default == MISSING}
            missing_fields = required_fields - set(features.keys())
            if missing_fields:
                raise ValueError(f"Missing required fields: {missing_fields}")

            # Convert bytes to strings and handle None values
            cleaned_features = {}
            for key, value in features.items():
                if isinstance(value, bytes):
                    cleaned_features[key] = value.decode('utf-8', errors='replace')
                elif value is None and key not in ['response_code', 'response_time', 'rating']:
                    cleaned_features[key] = ''  # Default empty string for required string fields
                else:
                    cleaned_features[key] = value

            # Set default values for optional fields if missing
            for field in ['response_code', 'response_time', 'rating']:
                if field not in cleaned_features:
                    cleaned_features[field] = None

            return RequestFeatures(**cleaned_features)

        except Exception as e:
            logger.error(f"Error preparing features: {e}", exc_info=True)
            raise

    def _validate_datatypes(self, df: pd.DataFrame) -> None:
        """Validate DataFrame datatypes match RequestFeatures specifications"""
        expected_types = {
            'url': str,
            'timestamp': float,
            'user_agent': str,
            'public_ip': str,
            'time_since_last_request': float,
            'referrer': str,
            'accept_language': str,
            'accept_encoding': str,
            'origin': str,
            'content_type': str,
            'x_requested_with': str,
            'connection': str,
            'cookies': str,
            'x_forwarded_for': str,
            'tls_fingerprint': str,
            'http_version': str,
            'request_method': str,
            'cache_control': str,
            'x_custom_headers': str,
            'response_code': 'Int64',  # Nullable integer type
            'response_time': float,
            'rating': 'Int64'  # Nullable integer type
        }

        for col, expected_type in expected_types.items():
            if col not in df.columns:
                raise ValueError(f"Missing column: {col}")
            
            if expected_type == 'Int64':
                df[col] = pd.to_numeric(df[col], errors='coerce').astype('Int64')
            elif expected_type == float:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            else:
                df[col] = df[col].astype(str)



    