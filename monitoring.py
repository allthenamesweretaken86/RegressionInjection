# monitoring.py
import time
import logging
import json
from datetime import datetime
from typing import Dict, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import os
logger = logging.getLogger(__name__)

@dataclass
class RequestMetrics:
    """Data class for storing request-specific metrics"""
    start_time: float
    end_time: Optional[float] = None
    status_code: Optional[int] = None
    cache_hit: bool = False
    error: Optional[str] = None

class MonitoringSystem:
    def __init__(self):
        """Initialize the monitoring system"""
        self.metrics = {
            'requests_processed': 0,
            'responses_processed': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0,
            'failed_requests': 0,
            'average_response_time': 0.0,
            'total_response_time': 0.0
        }
        self.request_metrics = {}
        self._create_metrics_directory()
        logger.info("Monitoring system initialized")

    def _create_metrics_directory(self) -> None:
        """Create directory for storing metrics"""
        try:
            os.makedirs('metrics', exist_ok=True)
        except Exception as e:
            logger.error(f"Error creating metrics directory: {e}")

    def start_request_timer(self, flow) -> None:
        """Start timing a request"""
        try:
            self.request_metrics[flow.id] = RequestMetrics(
                start_time=time.time()
            )
        except Exception as e:
            logger.error(f"Error starting request timer: {e}")

    def stop_request_timer(self, flow) -> None:
        """Stop timing a request and calculate duration"""
        try:
            if flow.id in self.request_metrics:
                metrics = self.request_metrics[flow.id]
                metrics.end_time = time.time()
                metrics.status_code = flow.response.status_code if flow.response else None
                
                duration = metrics.end_time - metrics.start_time
                self.metrics['total_response_time'] += duration
                self.metrics['requests_processed'] += 1
                
                # Update average response time
                self.metrics['average_response_time'] = (
                    self.metrics['total_response_time'] / 
                    self.metrics['requests_processed']
                )
                
                # Cleanup
                del self.request_metrics[flow.id]
        except Exception as e:
            logger.error(f"Error stopping request timer: {e}")

    def log_metric(self, metric_name: str, value: int = 1) -> None:
        """Log a metric"""
        try:
            if metric_name in self.metrics:
                self.metrics[metric_name] += value
            else:
                self.metrics[metric_name] = value
        except Exception as e:
            logger.error(f"Error logging metric: {e}")

    def record_cache_event(self, hit: bool) -> None:
        """Record cache hit or miss"""
        try:
            if hit:
                self.metrics['cache_hits'] += 1
            else:
                self.metrics['cache_misses'] += 1
        except Exception as e:
            logger.error(f"Error recording cache event: {e}")

    def record_error(self, error_type: str, error_message: str) -> None:
        """Record an error with better error handling"""
        try:
            self.metrics['errors'] += 1
            error_data = {
                'timestamp': datetime.now().isoformat(),
                'type': error_type,
                'message': str(error_message)  # Ensure error message is string
            }
            
            error_file = os.path.join('metrics', 'errors.jsonl')
            os.makedirs('metrics', exist_ok=True)  # Ensure metrics directory exists
            
            with open(error_file, 'a') as f:
                f.write(json.dumps(error_data) + '\n')
        except Exception as e:
            logger.error(f"Error recording error: {e}")

    def save_metrics(self) -> None:
        """Save current metrics to file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            metrics_file = f'metrics/metrics_{timestamp}.json'
            
            with open(metrics_file, 'w') as f:
                json.dump(self.metrics, f, indent=2)
            
            logger.info(f"Metrics saved to {metrics_file}")
        except Exception as e:
            logger.error(f"Error saving metrics: {e}")

    def get_current_metrics(self) -> Dict:
        """Get current metrics"""
        return self.metrics.copy()

    def reset_metrics(self) -> None:
        """Reset all metrics to initial values"""
        try:
            self.save_metrics()  # Save current metrics before resetting
            self.metrics = {k: 0 if isinstance(v, int) else 0.0 
                          for k, v in self.metrics.items()}
            self.request_metrics.clear()
        except Exception as e:
            logger.error(f"Error resetting metrics: {e}")