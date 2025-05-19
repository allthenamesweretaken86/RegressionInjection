# model.py
import os
import json
import logging
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, Tuple, List
from sklearn.tree import DecisionTreeRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score
import joblib
from config import (
    MODEL_FILE, PICKLES_DIR, MIN_TRAINING_SAMPLES,
    RATING_SCALE_MIN, RATING_SCALE_MAX
)

logger = logging.getLogger(__name__)

# For dynamic featurization of x_custom_headers
MAX_CUSTOM_HEADER_FEATURES = 20 # Limit how many distinct custom headers become features

class ModelManager:
    def __init__(self):
        self.model: Optional[DecisionTreeRegressor] = None
        self.scaler = StandardScaler()
        self.feature_columns: Optional[List[str]] = None
        self.numerical_cols_trained_on: Optional[List[str]] = None
        self.common_custom_header_keys: Optional[List[str]] = None # Store common X- header keys
        self.target_column = 'rating'
        self.model_trained_successfully_once = False
        self._load_model_and_dependencies()
        logger.info("ModelManager initialized (v4 - adaptive headers).")

    def _load_model_and_dependencies(self) -> None:
        model_path = MODEL_FILE
        scaler_path = os.path.join(PICKLES_DIR, 'dt_scaler_v2.joblib')
        feature_cols_path = os.path.join(PICKLES_DIR, 'dt_feature_columns_v2.json')
        numerical_cols_path = os.path.join(PICKLES_DIR, 'dt_numerical_cols_trained_on_v2.json')
        custom_header_keys_path = os.path.join(PICKLES_DIR, 'dt_common_custom_header_keys_v2.json')

        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                logger.info(f"Loaded model from {model_path}")
                if os.path.exists(scaler_path): self.scaler = joblib.load(scaler_path)
                if os.path.exists(feature_cols_path):
                    with open(feature_cols_path, 'r', encoding='utf-8') as f: self.feature_columns = json.load(f)
                if os.path.exists(numerical_cols_path):
                    with open(numerical_cols_path, 'r', encoding='utf-8') as f: self.numerical_cols_trained_on = json.load(f)
                if os.path.exists(custom_header_keys_path):
                    with open(custom_header_keys_path, 'r', encoding='utf-8') as f: self.common_custom_header_keys = json.load(f)
                self.model_trained_successfully_once = True
                logger.info("Loaded all model dependencies.")
            except Exception as e:
                logger.error(f"Error loading model/dependencies: {e}. Will create new.", exc_info=True)
                self._initialize_new_model_components()
        else:
            logger.info("No existing model found. New model on first training.")
            self._initialize_new_model_components()

    def _initialize_new_model_components(self):
        self.model = DecisionTreeRegressor(random_state=42, min_samples_split=10, min_samples_leaf=5, max_depth=20)
        self.scaler = StandardScaler()
        self.feature_columns = None
        self.numerical_cols_trained_on = None
        self.common_custom_header_keys = None
        self.model_trained_successfully_once = False

    def train(self, data_df: pd.DataFrame) -> Optional[Dict[str, float]]:
        if data_df.empty or len(data_df) < MIN_TRAINING_SAMPLES:
            logger.warning(f"Insufficient data for training: {len(data_df)}/{MIN_TRAINING_SAMPLES}")
            return None
        data_df_cleaned = data_df.dropna(subset=[self.target_column])
        if len(data_df_cleaned) < MIN_TRAINING_SAMPLES:
            logger.warning(f"Insufficient data after dropping NaNs in target: {len(data_df_cleaned)}/{MIN_TRAINING_SAMPLES}")
            return None
        logger.info(f"Starting model training with {len(data_df_cleaned)} samples.")
        try:
            X, y, prep_num_cols, prep_feat_cols, prep_custom_header_keys = self._prepare_data_for_training(data_df_cleaned.copy())
            if X is None or y is None or X.empty:
                logger.error("Data preparation failed or resulted in empty feature set.")
                return None

            self.feature_columns = prep_feat_cols
            self.numerical_cols_trained_on = prep_num_cols
            self.common_custom_header_keys = prep_custom_header_keys # Store for prediction phase

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            if self.numerical_cols_trained_on:
                X_train_num_scaled = self.scaler.fit_transform(X_train[self.numerical_cols_trained_on])
                X_test_num_scaled = self.scaler.transform(X_test[self.numerical_cols_trained_on])
                X_train_scaled = X_train.copy(); X_test_scaled = X_test.copy()
                X_train_scaled[self.numerical_cols_trained_on] = X_train_num_scaled
                X_test_scaled[self.numerical_cols_trained_on] = X_test_num_scaled
            else:
                X_train_scaled = X_train; X_test_scaled = X_test
            
            if self.model is None: self._initialize_new_model_components() # Should be initialized already

            self.model.fit(X_train_scaled, y_train)
            self.model_trained_successfully_once = True
            logger.info("Model fitting complete.")
            metrics = self._evaluate_model(X_test_scaled, y_test)
            
            if metrics and metrics.get('rmse', float('inf')) < 2.0: # Adjusted RMSE threshold for 0-10 scale
                self._save_model_and_dependencies()
                logger.info(f"Model trained and saved. Metrics: {metrics}")
            else:
                logger.warning(f"Model performance (RMSE: {metrics.get('rmse', 'N/A')}) may be suboptimal. Not saved unless first training.")
                if not self.model_trained_successfully_once:
                    self._save_model_and_dependencies() # Save even if suboptimal for first time
                    logger.info(f"Saving model (first training). Metrics: {metrics}")
            return metrics
        except Exception as e:
            logger.error(f"Error during model training: {e}", exc_info=True)
            return None

    def _prepare_data_for_training(self, data: pd.DataFrame) -> Tuple[Optional[pd.DataFrame], Optional[pd.Series], Optional[List[str]], Optional[List[str]], Optional[List[str]]]:
        try:
            y = data[self.target_column].astype(float)
            
            # Define features to drop initially
            # 'x_custom_headers' will be processed separately
            features_to_drop_base = [self.target_column, 'url', 'timestamp', 'public_ip', 'cookies', 'tls_fingerprint'] # Referrer, Origin kept for now
            X_candidate = data.drop(columns=[col for col in features_to_drop_base if col in data.columns], errors='ignore')

            # Process x_custom_headers
            custom_header_features_df = pd.DataFrame(index=X_candidate.index)
            common_custom_header_keys_identified = []
            if 'x_custom_headers' in X_candidate.columns:
                # Attempt to parse JSON string; fill errors with empty dict
                def parse_json_headers(json_str):
                    try: return json.loads(json_str) if pd.notna(json_str) and json_str else {}
                    except json.JSONDecodeError: return {}
                
                parsed_custom_headers = X_candidate['x_custom_headers'].apply(parse_json_headers)
                
                # Identify common custom header keys across the dataset
                all_custom_keys = pd.Series([k for d in parsed_custom_headers for k in d.keys()]).value_counts()
                common_custom_header_keys_identified = all_custom_keys.head(MAX_CUSTOM_HEADER_FEATURES).index.tolist()
                logger.info(f"Identified top {len(common_custom_header_keys_identified)} common custom header keys: {common_custom_header_keys_identified}")

                for header_key in common_custom_header_keys_identified:
                    custom_header_features_df[f'xhdr_{header_key}'] = parsed_custom_headers.apply(lambda d: d.get(header_key))
                
                X_candidate = X_candidate.drop(columns=['x_custom_headers']) # Drop original JSON string column

            # Combine base candidate features with new custom header features
            X_candidate = pd.concat([X_candidate, custom_header_features_df], axis=1)

            numerical_cols = X_candidate.select_dtypes(include=np.number).columns.tolist()
            categorical_cols = X_candidate.select_dtypes(exclude=np.number).columns.tolist()
            
            logger.debug(f"Numerical cols for prep: {numerical_cols}")
            logger.debug(f"Categorical cols for prep: {categorical_cols}")

            for col in categorical_cols:
                X_candidate[col] = X_candidate[col].astype(str).fillna('__MISSING__')
            X_processed = pd.get_dummies(X_candidate, columns=categorical_cols, prefix_sep='__', dummy_na=False)

            for col in numerical_cols:
                if col in X_processed.columns and X_processed[col].isnull().any():
                    fill_value = X_processed[col].median() 
                    X_processed[col] = X_processed[col].fillna(fill_value)
                    X_processed[col] = X_processed[col].astype(float) # Ensure float after fill
            
            if X_processed.empty: return None, None, None, None, None
            
            final_feature_columns = X_processed.columns.tolist()
            logger.info(f"Data prepared. X shape: {X_processed.shape}, y shape: {y.shape}. Features: {len(final_feature_columns)}")
            return X_processed, y, numerical_cols, final_feature_columns, common_custom_header_keys_identified
        except Exception as e:
            logger.error(f"Error preparing data: {e}", exc_info=True)
            return None, None, None, None, None

    def _preprocess_single_instance_for_prediction(self, features_instance: 'RequestFeatures') -> Optional[pd.DataFrame]:
        """Prepares a single RequestFeatures instance for prediction, aligning with training features."""
        if not self.feature_columns: # Model not trained yet or feature columns not set
            return None

        feature_dict = asdict(features_instance)
        input_df_row = pd.DataFrame([feature_dict])

        # Drop same base columns as in training
        features_to_drop_base = [self.target_column, 'url', 'timestamp', 'public_ip', 'cookies', 'tls_fingerprint']
        X_candidate_row = input_df_row.drop(columns=[col for col in features_to_drop_base if col in input_df_row.columns], errors='ignore')

        # Process x_custom_headers using self.common_custom_header_keys identified during training
        custom_header_features_for_row = pd.DataFrame(index=X_candidate_row.index)
        if 'x_custom_headers' in X_candidate_row.columns and self.common_custom_header_keys:
            try:
                parsed_custom_headers = json.loads(X_candidate_row['x_custom_headers'].iloc[0]) if pd.notna(X_candidate_row['x_custom_headers'].iloc[0]) and X_candidate_row['x_custom_headers'].iloc[0] else {}
            except json.JSONDecodeError:
                parsed_custom_headers = {}
            
            for header_key in self.common_custom_header_keys:
                custom_header_features_for_row[f'xhdr_{header_key}'] = parsed_custom_headers.get(header_key)
        
        X_candidate_row = X_candidate_row.drop(columns=['x_custom_headers'], errors='ignore')
        X_candidate_row = pd.concat([X_candidate_row, custom_header_features_for_row], axis=1)

        # One-hot encode categorical (must align with training features)
        current_categorical_cols = X_candidate_row.select_dtypes(exclude=np.number).columns.tolist()
        for col in current_categorical_cols:
            X_candidate_row[col] = X_candidate_row[col].astype(str).fillna('__MISSING__')
        
        X_processed_row = pd.get_dummies(X_candidate_row, columns=current_categorical_cols, prefix_sep='__', dummy_na=False)

        # Align columns with self.feature_columns
        for col in self.feature_columns:
            if col not in X_processed_row.columns:
                X_processed_row[col] = 0 # Add missing (likely a dummified feature not present in this instance)
        
        cols_to_drop_from_row = [col for col in X_processed_row.columns if col not in self.feature_columns]
        if cols_to_drop_from_row:
            X_processed_row = X_processed_row.drop(columns=cols_to_drop_from_row)
        
        X_processed_row = X_processed_row[self.feature_columns] # Ensure order and exact columns

        # Scale numerical features
        if self.numerical_cols_trained_on:
            # Fill NaNs that might appear in numerical columns before scaling
            for col in self.numerical_cols_trained_on:
                if X_processed_row[col].isnull().any():
                    X_processed_row[col] = X_processed_row[col].fillna(0) # Or a stored median from training
                X_processed_row[col] = X_processed_row[col].astype(float) # Ensure float

            try:
                X_processed_row[self.numerical_cols_trained_on] = self.scaler.transform(X_processed_row[self.numerical_cols_trained_on])
            except ValueError as ve: # If scaler encounters NaNs or unexpected values
                logger.error(f"ValueError during scaling for prediction: {ve}. Row data before scaling attempt: {X_processed_row[self.numerical_cols_trained_on]}", exc_info=True)
                return None # Cannot proceed if scaling fails
            except Exception as e:
                logger.error(f"General error during scaling for prediction: {e}", exc_info=True)
                return None


        return X_processed_row


    def predict_rating(self, features_instance: 'RequestFeatures') -> Optional[float]:
        if not self.model or not self.model_trained_successfully_once:
            logger.warning("Model not available for prediction.")
            return None
        
        X_processed_row = self._preprocess_single_instance_for_prediction(features_instance)
        if X_processed_row is None or X_processed_row.empty:
            logger.error("Failed to preprocess instance for prediction.")
            return None
        
        try:
            prediction = self.model.predict(X_processed_row)
            predicted_rating = float(prediction[0])
            predicted_rating = max(RATING_SCALE_MIN, min(RATING_SCALE_MAX, predicted_rating))
            logger.debug(f"Predicted rating: {predicted_rating:.2f}")
            return predicted_rating
        except Exception as e:
            logger.error(f"Error during rating prediction: {e}", exc_info=True)
            return None

    def get_feature_importances(self) -> Optional[Dict[str, float]]:
        if self.model and self.model_trained_successfully_once and hasattr(self.model, 'feature_importances_') and self.feature_columns:
            importances = self.model.feature_importances_
            return dict(sorted(zip(self.feature_columns, importances), key=lambda item: item[1], reverse=True))
        return None

    def _save_model_and_dependencies(self) -> None:
        try:
            os.makedirs(PICKLES_DIR, exist_ok=True)
            if self.model: joblib.dump(self.model, MODEL_FILE)
            if self.scaler and self.numerical_cols_trained_on: 
                joblib.dump(self.scaler, os.path.join(PICKLES_DIR, 'dt_scaler_v2.joblib'))
            if self.feature_columns:
                with open(os.path.join(PICKLES_DIR, 'dt_feature_columns_v2.json'), 'w') as f: json.dump(self.feature_columns, f)
            if self.numerical_cols_trained_on:
                with open(os.path.join(PICKLES_DIR, 'dt_numerical_cols_trained_on_v2.json'), 'w') as f: json.dump(self.numerical_cols_trained_on, f)
            if self.common_custom_header_keys is not None: # Save even if empty list
                with open(os.path.join(PICKLES_DIR, 'dt_common_custom_header_keys_v2.json'), 'w') as f: json.dump(self.common_custom_header_keys, f)
            logger.info("Model and dependencies saved successfully.")
        except Exception as e:
            logger.error(f"Error saving model/dependencies: {e}", exc_info=True)

    def get_high_quality_request_patterns(self, training_data_df: pd.DataFrame, top_n=15) -> List[Dict[str, Any]]:
        if training_data_df.empty: return []
        
        # Use a higher threshold for "high quality" on 0-10 scale
        high_rated_df = training_data_df[training_data_df[self.target_column] >= 8.0].copy()
        if high_rated_df.empty:
            logger.info("No requests found with rating >= 8.0 for pattern generation.")
            # Fallback to slightly lower threshold if needed
            high_rated_df = training_data_df[training_data_df[self.target_column] >= 7.0].copy()
            if high_rated_df.empty:
                logger.info("No requests found with rating >= 7.0 either.")
                return []
        
        # These are the original features RetryManager can work with
        # Should match fields in RequestFeatures that represent direct request parameters/headers
        pattern_features = [
            'user_agent', 'accept', 'accept_language', 'accept_encoding', 
            'connection', 'host', 'origin', 'referer', 'cache_control', 
            'content_type', 'request_method',
            'sec_fetch_dest', 'sec_fetch_mode', 'sec_fetch_site',
            'x_custom_headers' # RetryManager might need to parse this JSON string
        ]
        existing_pattern_features = [col for col in pattern_features if col in high_rated_df.columns]
        if not existing_pattern_features: return []

        top_patterns_df = high_rated_df.sort_values(by=self.target_column, ascending=False).head(top_n)
        patterns_list = []
        for _, row in top_patterns_df.iterrows():
            pattern = {col: row[col] for col in existing_pattern_features if pd.notna(row[col]) and row[col] != ""}
            if pattern: patterns_list.append(pattern)
        
        logger.info(f"Generated {len(patterns_list)} high-quality request patterns for RetryManager.")
        return patterns_list

    def _evaluate_model(self, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, float]:
        """Evaluates the model and returns performance metrics."""
        try:
            predictions = self.model.predict(X_test)
            mse = mean_squared_error(y_test, predictions)
            rmse = np.sqrt(mse)
            r2 = r2_score(y_test, predictions)
            logger.info(f"Model Evaluation - RMSE: {rmse:.3f}, MSE: {mse:.3f}, R^2: {r2:.3f}")
            return {'mse': mse, 'rmse': rmse, 'r2_score': r2}
        except Exception as e:
            logger.error(f"Error evaluating model: {e}", exc_info=True)
            return {'mse': float('inf'), 'rmse': float('inf'), 'r2_score': float('-inf')}

