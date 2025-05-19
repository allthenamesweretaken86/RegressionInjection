# retry_manager.py
import time
import logging
import random
import pandas as pd
from typing import Dict, Optional, List, Any
from mitmproxy import http # For type hinting flow

from model import ModelManager # To get successful patterns
from request_features import RequestFeaturesModel # To get training data for pattern generation
from config import NUM_RETRIES, RETRY_THRESHOLD_RATING # RETRY_THRESHOLD_RATING might not be used here directly

logger = logging.getLogger(__name__)

# RetryRequest dataclass would be beneficial here if not already defined elsewhere
# For simplicity, using Dicts for now.
# from dataclasses import dataclass
# @dataclass
# class RetryJob:
#     flow_id: str
#     original_flow: http.HTTPFlow # Store the original flow for replaying/modifying
#     url: str
#     method: str
#     headers: Dict[str, str] # Original headers
#     content: Optional[bytes]
#     attempt_count: int
#     next_retry_time: float # Unix timestamp
#     last_error: Optional[str] = None
#     # current_optimized_headers: Optional[Dict[str, str]] = None


class RetryManager:
    def __init__(self, model_manager: ModelManager, training_data_provider: RequestFeaturesModel, max_retries: int = NUM_RETRIES, initial_delay_s: int = 5):
        self.model_manager = model_manager
        self.training_data_provider = training_data_provider # To get data for pattern analysis
        self.max_retries = max_retries
        self.initial_delay_s = initial_delay_s
        self.retry_queue: Dict[str, Dict[str, Any]] = {} # flow.id -> retry_job_dict
        logger.info(f"RetryManager initialized. Max retries: {self.max_retries}, Initial delay: {self.initial_delay_s}s.")

    def add_failed_request(self, flow: http.HTTPFlow) -> None:
        """Adds a failed request (based on low rating or error) to the retry queue."""
        if flow.id in self.retry_queue:
            logger.debug(f"Request {flow.id} for {flow.request.url} already in retry queue. Skipping.")
            return

        # Check if max retries for this original request have already been attempted
        # This needs more sophisticated tracking if flows are re-issued with new IDs by mitmproxy's replay mechanism.
        # For now, assuming flow.id is unique enough for initial add.

        try:
            # Convert mitmproxy headers (Fields) to a simple dict of str:str
            original_headers = {k.decode('utf-8', 'ignore'): v.decode('utf-8', 'ignore') 
                                for k, v in flow.request.headers.fields}

            retry_job = {
                "flow_id": flow.id, # Original flow ID for tracking
                "original_url": flow.request.url,
                "original_method": flow.request.method,
                "original_headers": original_headers,
                "original_content": flow.request.content, # Content as bytes
                "attempt_count": 0, # This will be the first retry attempt when processed
                "next_retry_time": self._calculate_next_retry_time(0),
                "last_status_code": flow.response.status_code if flow.response else None,
                "last_error_message": str(flow.error) if flow.error else None,
                "optimization_attempts": 0, # How many times we tried different optimization strategies
            }
            
            # Initial optimization for the first retry attempt
            # retry_job["current_optimized_headers"] = self.generate_optimized_headers(retry_job)

            self.retry_queue[flow.id] = retry_job
            logger.info(f"Added request {flow.id} for {flow.request.url} to retry queue. Next attempt around {time.ctime(retry_job['next_retry_time'])}.")

        except Exception as e:
            logger.error(f"Error adding request {flow.id} ({flow.request.url}) to retry queue: {e}", exc_info=True)

    def _calculate_next_retry_time(self, attempt_num: int) -> float:
        """Calculates next retry time with exponential backoff and jitter."""
        delay = self.initial_delay_s * (2 ** attempt_num)
        jitter = random.uniform(0, delay * 0.1) # Add up to 10% jitter
        return time.time() + delay + jitter

    def generate_optimized_headers(self, retry_job: Dict[str, Any]) -> Dict[str, str]:
        """
        Generates a new set of headers for the next retry attempt.
        Uses ModelManager to get high-quality patterns.
        """
        # Fallback to original headers if no optimization is found
        optimized_headers = retry_job["original_headers"].copy() 
        
        try:
            # Get current training data from the provider
            training_df = self.training_data_provider.get_training_data_for_model()
            if training_df.empty:
                logger.warning("Training data is empty, cannot generate model-based optimized headers. Using defaults/original.")
            else:
                # Get high-quality patterns from ModelManager
                # top_n can be adjusted, or try different patterns each optimization attempt
                # The number of patterns to try depends on retry_job["optimization_attempts"]
                num_patterns_to_consider = 5 + retry_job["optimization_attempts"]
                high_quality_patterns = self.model_manager.get_high_quality_request_patterns(training_df, top_n=num_patterns_to_consider)

                if high_quality_patterns:
                    # Strategy: try a different pattern from the top list for each optimization attempt
                    pattern_index = retry_job["optimization_attempts"] % len(high_quality_patterns)
                    chosen_pattern_dict = high_quality_patterns[pattern_index]
                    
                    logger.info(f"Attempting optimization with pattern {pattern_index+1}/{len(high_quality_patterns)}: {chosen_pattern_dict}")

                    # Merge/replace original headers with those from the chosen pattern
                    # Be careful about case-sensitivity if the target server is picky.
                    # Store headers as str:str.
                    for key, value in chosen_pattern_dict.items():
                        # Ensure key is a string (it should be from get_high_quality_request_patterns)
                        # and value is also a string.
                        optimized_headers[str(key)] = str(value)
                    
                    # Specific common headers to prioritize from pattern if available
                    # Example: User-Agent is often critical
                    if 'user_agent' in chosen_pattern_dict and chosen_pattern_dict['user_agent']:
                        optimized_headers['User-Agent'] = str(chosen_pattern_dict['user_agent'])
                    if 'accept_language' in chosen_pattern_dict and chosen_pattern_dict['accept_language']:
                        optimized_headers['Accept-Language'] = str(chosen_pattern_dict['accept_language'])
                    
                    logger.info(f"Generated optimized headers for {retry_job['original_url']}: {optimized_headers}")
                    retry_job["optimization_attempts"] += 1
                    return optimized_headers
                else:
                    logger.info("No high-quality patterns found from model. Trying default optimizations.")

            # Fallback to default optimizations if model provides no patterns
            # This can be a predefined list of common "good" headers
            default_uas = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.0.3 Safari/537.36",
            ]
            optimized_headers['User-Agent'] = random.choice(default_uas)
            optimized_headers['Accept'] = "*/*"
            optimized_headers['Accept-Language'] = "en-US,en;q=0.9"
            # Remove potentially problematic headers for retries
            for problematic_header in ["If-None-Match", "If-Modified-Since", "Etag"]:
                optimized_headers.pop(problematic_header, None)
            
            logger.info(f"Applied default header optimizations for {retry_job['original_url']}.")
            retry_job["optimization_attempts"] += 1 # Count this as an optimization attempt too

        except Exception as e:
            logger.error(f"Error generating optimized headers for {retry_job['original_url']}: {e}", exc_info=True)
            # Fallback to original headers on error
            return retry_job["original_headers"].copy()
        
        return optimized_headers


    def get_requests_to_retry(self) -> List[Dict[str, Any]]:
        """
        Gets requests from the queue that are ready for a retry attempt.
        This method would be called periodically by the main proxy logic (e.g., in a tick handler if mitmproxy supported it,
        or a separate thread, or just before processing new requests).
        For now, it's designed to be called, and it returns a list of flows to be replayed.
        """
        ready_for_retry = []
        current_time = time.time()
        flow_ids_to_remove = []

        for flow_id, job in list(self.retry_queue.items()): # Iterate over a copy for safe removal
            if job["attempt_count"] >= self.max_retries:
                logger.warning(f"Max retries ({self.max_retries}) reached for {job['original_url']} (ID: {flow_id}). Removing from queue.")
                flow_ids_to_remove.append(flow_id)
                continue

            if current_time >= job["next_retry_time"]:
                job["attempt_count"] += 1
                # Generate new set of optimized headers for this attempt
                job["current_optimized_headers"] = self.generate_optimized_headers(job)
                
                logger.info(f"Request {job['original_url']} (ID: {flow_id}) is ready for retry attempt #{job['attempt_count']}.")
                ready_for_retry.append(job) # Add the whole job dict
                # The job remains in queue until success or max_retries; only next_retry_time is updated upon failure.
            
        for flow_id in flow_ids_to_remove:
            if flow_id in self.retry_queue:
                del self.retry_queue[flow_id]
        
        return ready_for_retry

    def update_retry_outcome(self, original_flow_id: str, success: bool, new_flow: Optional[http.HTTPFlow] = None) -> None:
        """
        Updates the status of a retry attempt.
        If successful, removes from queue. If failed, schedules next retry or removes if maxed out.
        """
        if original_flow_id not in self.retry_queue:
            logger.warning(f"Original flow ID {original_flow_id} not found in retry queue for outcome update.")
            return

        job = self.retry_queue[original_flow_id]

        if success:
            logger.info(f"Retry attempt #{job['attempt_count']} for {job['original_url']} (ID: {original_flow_id}) was SUCCESSFUL. Removing from queue.")
            # Potentially log the successful optimized_headers to the model via request_features_manager
            # This requires the main loop to collect features from the *successful retry flow* (new_flow)
            # and associate them with the fact that these headers worked.
            # For now, model learns from all traffic, including successful retries processed by main.response.
            del self.retry_queue[original_flow_id]
        else:
            job["last_status_code"] = new_flow.response.status_code if new_flow and new_flow.response else None
            job["last_error_message"] = str(new_flow.error) if new_flow and new_flow.error else "Retry failed, unknown error or low rating."
            
            if job["attempt_count"] < self.max_retries:
                job["next_retry_time"] = self._calculate_next_retry_time(job["attempt_count"])
                logger.warning(
                    f"Retry attempt #{job['attempt_count']} for {job['original_url']} (ID: {original_flow_id}) FAILED. "
                    f"Status: {job['last_status_code']}, Error: {job['last_error_message']}. "
                    f"Next attempt around {time.ctime(job['next_retry_time'])}."
                )
            else: # Max retries reached on this failure
                logger.error(
                    f"Max retries ({self.max_retries}) reached for {job['original_url']} (ID: {original_flow_id}) after FAILED attempt #{job['attempt_count']}. "
                    f"Final Status: {job['last_status_code']}, Error: {job['last_error_message']}. Removing from queue."
                )
                del self.retry_queue[original_flow_id]

    # Note: The actual replaying of requests (creating a new flow with modified headers)
    # needs to be handled by the main proxy script using mitmproxy's `ctx.master.commands.call("replay.client", [flow_to_replay])`
    # or similar mechanism. This RetryManager prepares the *data* for the retry.
