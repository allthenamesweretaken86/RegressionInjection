# monitoring.py
import time
import logging
import json
from datetime import datetime
from typing import Dict, Optional, Any, Union # Added Union
from dataclasses import dataclass
import os
import numpy as np # For serializing numpy types if they appear in metrics

logger = logging.getLogger(__name__)

@dataclass
class ActiveTimerInfo:
    """Data class for storing active request timer information."""
    flow_id: str
    start_time_perf_counter: float

class MonitoringSystem:
    def __init__(self):
        """Initialize the monitoring system."""
        self.metrics: Dict[str, Any] = {
            'requests_processed_total': 0,
            'responses_processed_from_cache': 0,
            'responses_processed_from_server': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors_logged': 0,
            'request_phase_errors': 0,
            'response_phase_errors': 0,
            'addon_shutdown_errors': 0,
            'failed_requests_for_retry': 0,
            'failed_requests_for_retry_noconn': 0,
            'average_response_time_ms': 0.0,
            'total_response_time_ms': 0.0,
            'response_count_for_avg': 0
        }
        self.active_request_timers: Dict[str, ActiveTimerInfo] = {}
        self._create_metrics_directory()
        logger.info("Monitoring system initialized (v4_final_fix).")

    def _create_metrics_directory(self) -> None:
        try:
            os.makedirs('metrics', exist_ok=True)
        except Exception as e:
            logger.error(f"Error creating metrics directory 'metrics/': {e}")

    def start_request_timer(self, flow_id: str) -> None:
        try:
            if flow_id in self.active_request_timers:
                logger.warning(f"Timer for flow {flow_id} already started. Overwriting.")
            self.active_request_timers[flow_id] = ActiveTimerInfo(
                flow_id=flow_id,
                start_time_perf_counter=time.perf_counter()
            )
            logger.debug(f"Started timer for flow {flow_id}")
        except Exception as e:
            logger.error(f"Error starting request timer for flow ID {flow_id}: {e}", exc_info=True)

    def stop_request_timer(self, flow_id: str, status_code: Optional[int] = None) -> None:
        try:
            if flow_id in self.active_request_timers:
                timer_info = self.active_request_timers.pop(flow_id)
                end_time_perf_counter = time.perf_counter()
                duration_ms = (end_time_perf_counter - timer_info.start_time_perf_counter) * 1000
                
                self.metrics['total_response_time_ms'] += duration_ms
                self.metrics['response_count_for_avg'] += 1
                
                if self.metrics['response_count_for_avg'] > 0:
                    self.metrics['average_response_time_ms'] = (
                        self.metrics['total_response_time_ms'] / 
                        self.metrics['response_count_for_avg']
                    )
                logger.debug(f"Stopped timer for flow {flow_id}. Duration: {duration_ms:.2f}ms, Status: {status_code if status_code is not None else 'N/A'}")
            else:
                logger.warning(f"Attempted to stop timer for flow {flow_id}, but no active timer found.")
        except Exception as e:
            logger.error(f"Error stopping request timer for flow ID {flow_id}: {e}", exc_info=True)

    def is_timer_running(self, flow_id: str) -> bool:
        return flow_id in self.active_request_timers

    def log_metric(self, metric_name: str, value: Union[int, float] = 1) -> None: # Added Union import
        try:
            if metric_name in self.metrics:
                self.metrics[metric_name] += value
            else:
                self.metrics[metric_name] = value
                logger.info(f"New custom metric '{metric_name}' initialized to {value}.")
        except TypeError:
             logger.error(f"TypeError logging metric '{metric_name}'. Current: {self.metrics.get(metric_name)}, trying to add: {value}")
             if isinstance(value, float) and isinstance(self.metrics.get(metric_name), int):
                 self.metrics[metric_name] = float(self.metrics[metric_name]) + value
             elif isinstance(value, int) and isinstance(self.metrics.get(metric_name), float):
                  self.metrics[metric_name] += float(value)
        except Exception as e:
            logger.error(f"Error logging metric '{metric_name}': {e}")

    def record_cache_event(self, hit: bool) -> None:
        if hit: self.log_metric('cache_hits')
        else: self.log_metric('cache_misses')

    def record_error(self, error_source_type: str, error_message: str, flow_id: Optional[str] = None) -> None:
        try:
            self.log_metric('errors_logged')
            if error_source_type in self.metrics:
                 self.log_metric(error_source_type)
            
            error_data = {
                'timestamp': datetime.now().isoformat(), 'type': error_source_type,
                'message': str(error_message), 'flow_id': flow_id if flow_id else "N/A"
            }
            error_file = os.path.join('metrics', 'runtime_errors.jsonl')
            with open(error_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(error_data) + '\n')
        except Exception as e:
            logger.error(f"Critical error in MonitoringSystem.record_error: {e}", exc_info=True)

    def save_metrics(self) -> None:
        try:
            self._create_metrics_directory() 
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            metrics_file = os.path.join('metrics', f'system_metrics_{timestamp}.json')
            serializable_metrics = {k: (float(v) if isinstance(v, (np.float_, np.int_)) else v) for k, v in self.metrics.items()}
            with open(metrics_file, 'w', encoding='utf-8') as f:
                json.dump(serializable_metrics, f, indent=4)
            logger.info(f"System metrics saved to {metrics_file}")
        except ImportError: 
            with open(metrics_file, 'w', encoding='utf-8') as f: # type: ignore
                json.dump(self.metrics, f, indent=4)
            logger.info(f"System metrics saved to {metrics_file} (numpy not available).") # type: ignore
        except Exception as e:
            logger.error(f"Error saving system metrics: {e}", exc_info=True)

    def get_current_metrics(self) -> Dict[str, Any]:
        return self.metrics.copy()