# model.py
import os
import pickle
import json
import logging
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import joblib
from config import MODEL_FILE, PICKLES_DIR, TRAINING_DATA_FILE, MIN_TRAINING_SAMPLES, MAX_RECORDS

logger = logging.getLogger(__name__)

class ModelManager:
    def __init__(self):
        """Initialize the model manager with proper data structures"""
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = None
        self.target_column = 'rating'
        self.model_trained = False
        self.training_data = self._load_training_data()
        self.successful_features = []
        self._load_or_create_model()
        logger.info("ModelManager initialized")

    def _load_or_create_model(self) -> None:
        """Load existing model or create new one"""
        try:
            if os.path.exists(MODEL_FILE):
                self.model = joblib.load(MODEL_FILE)
                self.model_trained = True
                logger.info("Loaded existing model")
            else:
                self.model = LogisticRegression(
                    max_iter=1000,
                    class_weight='balanced',
                    random_state=42
                )
                logger.info("Created new model")
        except Exception as e:
            logger.warning(f"Could not load existing model: {e}")
            self.model = LogisticRegression(
                max_iter=1000,
                class_weight='balanced',
                random_state=42
            )
            logger.info("Created new model as fallback")

    def _load_training_data(self) -> pd.DataFrame:
        """Load training data from disk or create empty DataFrame with correct structure"""
        try:
            if os.path.exists(TRAINING_DATA_FILE):
                df = pd.read_pickle(TRAINING_DATA_FILE)
                logger.info(f"Loaded training data with {len(df)} records")
                return df
            else:
                # Create empty DataFrame with correct columns
                columns = [
                    'url', 'timestamp', 'user_agent', 'public_ip', 
                    'time_since_last_request', 'referrer', 'accept_language',
                    'accept_encoding', 'origin', 'content_type', 
                    'x_requested_with', 'connection', 'cookies',
                    'x_forwarded_for', 'tls_fingerprint', 'http_version',
                    'request_method', 'cache_control', 'x_custom_headers',
                    'response_code', 'response_time', 'rating'
                ]
                logger.info("Created new empty training data DataFrame")
                return pd.DataFrame(columns=columns)
        except Exception as e:
            logger.error(f"Error loading training data: {e}", exc_info=True)
            return pd.DataFrame()

    def train(self, data: pd.DataFrame) -> Optional[Dict[str, float]]:
        """Train the model with new data"""
        try:
            if len(data) < MIN_TRAINING_SAMPLES:
                logger.warning(f"Insufficient data for training: {len(data)} samples")
                return None

            # Prepare data
            X, y = self._prepare_data(data)
            if X is None or y is None:
                return None

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

            # Fit scaler and transform data
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # Train model
            self.model.fit(X_train_scaled, y_train)
            self.model_trained = True

            # Evaluate and save
            metrics = self._evaluate_model(X_test_scaled, y_test)
            
            if metrics['accuracy'] > 0.7:
                self._save_model()
                logger.info(f"Model trained successfully: {metrics}")
            else:
                logger.warning(f"Model performance below threshold: {metrics}")

            return metrics

        except Exception as e:
            logger.error(f"Error training model: {e}", exc_info=True)
            return None

    def _prepare_data(self, data: pd.DataFrame) -> Tuple[Optional[pd.DataFrame], Optional[pd.Series]]:
        """Prepare data for training"""
        try:
            # Remove rows with missing values
            data = data.dropna(subset=[self.target_column])
            
            if self.target_column not in data.columns:
                raise ValueError(f"Target column '{self.target_column}' not found")

            # Define numerical and categorical columns
            numerical_cols = ['timestamp', 'time_since_last_request', 'response_time']
            
            # Create feature DataFrame
            X = pd.DataFrame()
            
            # Handle numerical columns
            for col in numerical_cols:
                if col in data.columns:
                    X[col] = pd.to_numeric(data[col], errors='coerce')
            
            # Handle categorical columns using one-hot encoding
            categorical_cols = [col for col in data.columns 
                              if col not in numerical_cols + [self.target_column]]
            
            for col in categorical_cols:
                if col in data.columns:
                    dummies = pd.get_dummies(data[col], prefix=col, dummy_na=True)
                    X = pd.concat([X, dummies], axis=1)
            
            # Get target variable
            y = data[self.target_column]
            
            # Store feature columns for future predictions
            self.feature_columns = X.columns.tolist()
            
            return X, y

        except Exception as e:
            logger.error(f"Error preparing data: {e}", exc_info=True)
            return None, None

    def get_successful_patterns(self) -> pd.DataFrame:
        """Get patterns from successful requests (rating > 2)"""
        try:
            if self.training_data is None:
                self.training_data = self._load_training_data()

            if self.training_data.empty:
                logger.warning("Training data is empty")
                return pd.DataFrame()

            # Filter for successful requests
            successful = self.training_data[
                (self.training_data['rating'].notna()) & 
                (self.training_data['rating'] > 2)
            ].copy()

            if successful.empty:
                logger.warning("No successful patterns found")
                return pd.DataFrame()

            # Calculate success score
            successful['success_score'] = successful.apply(
                lambda row: self._calculate_success_score(row),
                axis=1
            )

            # Sort by success score
            successful = successful.sort_values('success_score', ascending=False)

            logger.info(f"Found {len(successful)} successful patterns")
            return successful

        except Exception as e:
            logger.error(f"Error getting successful patterns: {e}", exc_info=True)
            return pd.DataFrame()

    def record_successful_features(self, features: Dict) -> None:
        """Record successful feature combinations for future optimization"""
        try:
            if features is None:
                logger.warning("Received None features, skipping")
                return

            # Clean and validate features
            cleaned_features = self._clean_feature_dict(features)
            
            # Convert to DataFrame row
            new_row = pd.DataFrame([cleaned_features])
            
            # Add to training data
            if self.training_data is None:
                self.training_data = self._load_training_data()
            
            self.training_data = pd.concat([self.training_data, new_row], ignore_index=True)

            # Keep only the last MAX_RECORDS rows
            if len(self.training_data) > MAX_RECORDS:
                self.training_data = self.training_data.iloc[-MAX_RECORDS:]

            # Save training data
            self._save_training_data()
            
            # Keep successful features list updated
            self.successful_features.append(cleaned_features)
            if len(self.successful_features) > 1000:
                self.successful_features = self.successful_features[-1000:]

            logger.info(f"Recorded successful feature combination. Total patterns: {len(self.training_data)}")

        except Exception as e:
            logger.error(f"Error recording successful features: {e}", exc_info=True)

    def _clean_feature_dict(self, features: Dict) -> Dict:
        """Clean and validate feature dictionary"""
        cleaned = {}
        try:
            for key, value in features.items():
                # Convert bytes to strings
                if isinstance(value, bytes):
                    cleaned[key] = value.decode('utf-8', errors='replace')
                # Handle None values
                elif value is None:
                    cleaned[key] = None
                # Convert all other values to string
                else:
                    cleaned[key] = str(value)

            # Ensure all required columns are present
            required_columns = self._load_training_data().columns
            for col in required_columns:
                if col not in cleaned:
                    cleaned[col] = None

            return cleaned
        except Exception as e:
            logger.error(f"Error cleaning features: {e}")
            return features

    def _save_training_data(self) -> None:
        """Save training data to disk"""
        try:
            if self.training_data is not None and not self.training_data.empty:
                # Ensure directory exists
                os.makedirs(os.path.dirname(TRAINING_DATA_FILE), exist_ok=True)
                
                # Save data
                self.training_data.to_pickle(TRAINING_DATA_FILE)
                logger.debug(f"Saved training data with {len(self.training_data)} records")
                
                # Also save a CSV backup periodically
                if len(self.training_data) % 100 == 0:
                    backup_file = TRAINING_DATA_FILE.replace('.pkl', '.csv')
                    self.training_data.to_csv(backup_file, index=False)
                    logger.info(f"Created CSV backup with {len(self.training_data)} records")

        except Exception as e:
            logger.error(f"Error saving training data: {e}", exc_info=True)

    def _calculate_success_score(self, row: pd.Series) -> float:
        """Calculate success score with proper error handling"""
        try:
            score = 0.0
            
            # Rating score
            if pd.notna(row.get('rating')):
                score += float(row['rating']) * 2
            
            # Response time score
            if pd.notna(row.get('response_time')):
                response_time = float(row['response_time'])
                if response_time > 0:
                    score += 1 / response_time
            
            # Status code score
            if pd.notna(row.get('response_code')):
                response_code = int(row['response_code'])
                if 200 <= response_code < 300:
                    score += 5
                elif 300 <= response_code < 400:
                    score += 3
            
            return score
            
        except Exception as e:
            logger.error(f"Error calculating success score: {e}")
            return 0.0

    def _save_model(self) -> None:
        """Save the current model state"""
        try:
            if self.model_trained:
                joblib.dump(self.model, MODEL_FILE)
                logger.info("Saved model to disk")
                
                # Save scaler if it's been fitted
                if hasattr(self.scaler, 'mean_'):
                    scaler_file = os.path.join(PICKLES_DIR, 'scaler.joblib')
                    joblib.dump(self.scaler, scaler_file)
                    logger.info("Saved scaler to disk")
        except Exception as e:
            logger.error(f"Error saving model: {e}")

    def _evaluate_model(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
        """Evaluate model performance"""
        try:
            predictions = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, predictions)
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_test, predictions, average='weighted'
            )

            return {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1
            }

        except Exception as e:
            logger.error(f"Error evaluating model: {e}")
            return {
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0
            }