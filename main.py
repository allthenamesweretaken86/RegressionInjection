# main.py
import logging
from mitmproxy import ctx, http
from requests_cache import CachedSession, install_cache, get_cache
from datetime import timedelta
from request_features import RequestFeaturesModel
from monitoring import MonitoringSystem
from retry_manager import RetryManager
import requests
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='proxy.log'
)
logger = logging.getLogger(__name__)

class ProxyController:
    def __init__(self):
        # Initialize global cache with 4-hour expiry
        install_cache(
            'proxy_cache',
            backend='sqlite',
            expire_after=timedelta(hours=4),
            allowable_methods=('GET', 'POST', 'HEAD'),
            stale_if_error=True
        )
        self.cache = get_cache()
        self.request_model = RequestFeaturesModel()
        self.monitoring = MonitoringSystem()
        self.retry_manager = RetryManager()
        logger.info("Proxy controller initialized")

    def _convert_flow_to_request(self, flow: http.HTTPFlow) -> requests.Request:
        """Convert mitmproxy flow to requests.Request object"""
        try:
            # Convert headers from bytes to strings
            headers = {}
            for k, v in flow.request.headers.items():
                try:
                    key = k.decode('utf-8') if isinstance(k, bytes) else str(k)
                    value = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                    headers[key] = value
                except Exception as e:
                    logger.warning(f"Failed to decode header {k}: {e}")
                    continue

            # Create request object
            req = requests.Request(
                method=flow.request.method,
                url=flow.request.url,
                headers=headers,
                data=flow.request.content if flow.request.content else None
            )
            
            # Prepare the request (this sets all the necessary attributes)
            prepared_req = req.prepare()
            
            return prepared_req
            
        except Exception as e:
            logger.error(f"Error converting flow to request: {e}")
            raise

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle incoming requests"""
        try:
            self.monitoring.start_request_timer(flow)
            
            # Convert flow to requests.Request object
            req = self._convert_flow_to_request(flow)
            
            # Check if request is cached using contains()
            if self.cache.contains(request=req):
                logger.debug(f"Cache hit for: {flow.request.url}")
                self.monitoring.log_metric('cache_hits')
                
                # Get cached response using the cache key
                cache_key = self.cache.create_key(req)
                cached_response = self.cache.get_response(cache_key)
                if cached_response:
                    self._serve_cached_response(flow, cached_response)
            else:
                logger.debug(f"Cache miss for: {flow.request.url}")
                self.monitoring.log_metric('cache_misses')
            
            self.monitoring.log_metric('requests_processed')
            
        except Exception as e:
            logger.error(f"Error processing request: {e}", exc_info=True)
            self.monitoring.log_metric('request_errors')
            self.monitoring.record_error('request_error', str(e))

    def _serve_cached_response(self, flow: http.HTTPFlow, cached_response) -> None:
        """Serve a cached response"""
        try:
            # Convert headers to bytes for mitmproxy
            headers = []
            for k, v in cached_response.headers.items():
                try:
                    key = k.encode('utf-8') if isinstance(k, str) else k
                    value = v.encode('utf-8') if isinstance(v, str) else v
                    headers.append((key, value))
                except Exception as e:
                    logger.warning(f"Failed to encode header {k}: {e}")
                    continue

            # Create mitmproxy response
            response = http.Response.make(
                status_code=cached_response.status_code,
                content=cached_response.content,
                headers=headers
            )
            
            flow.response = response
            logger.debug(f"Served cached response for: {flow.request.url}")
            
        except Exception as e:
            logger.error(f"Error serving cached response: {e}", exc_info=True)

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle responses"""
        try:
            self.monitoring.stop_request_timer(flow)
            
            # Update cache if response is cacheable
            if self._is_response_cacheable(flow):
                self._update_cache(flow)
                
            # Process response for model and monitoring
            response_info = self._process_response(flow)
            
            if response_info and isinstance(response_info, dict):
                rating = response_info.get('rating')
                if rating is not None and rating <= 2:
                    self.retry_manager.add_failed_request(flow)
                    self.monitoring.log_metric('failed_requests')
            
            self.monitoring.log_metric('responses_processed')
            
        except Exception as e:
            logger.error(f"Error processing response: {e}", exc_info=True)
            self.monitoring.log_metric('response_errors')
            self.monitoring.record_error('response_error', str(e))

    def _is_response_cacheable(self, flow: http.HTTPFlow) -> bool:
        """Check if response should be cached"""
        if not flow.response:
            return False
            
        if flow.response.status_code >= 400:
            return False
            
        cache_control = flow.response.headers.get("Cache-Control", "").lower()
        if "no-store" in cache_control or "no-cache" in cache_control:
            return False
            
        if flow.request.method not in ["GET", "HEAD", "POST"]:
            return False
            
        return True

    def _update_cache(self, flow: http.HTTPFlow) -> None:
        """Update cache with response"""
        try:
            # Convert request
            req = self._convert_flow_to_request(flow)
            
            # Create a requests.Response-like object
            response = requests.Response()
            response.status_code = flow.response.status_code
            response._content = flow.response.content
            response.headers = {
                k.decode('utf-8', 'ignore'): v.decode('utf-8', 'ignore') 
                for k, v in flow.response.headers.items()
            }
            response.url = flow.request.url
            response.request = req
            
            # Save to cache
            self.cache.save_response(response)
            
            logger.debug(f"Cached response for: {flow.request.url}")
            
        except Exception as e:
            logger.error(f"Error updating cache: {e}")

    def _process_response(self, flow: http.HTTPFlow) -> dict:
        """Process response for model and return response info"""
        response_time = (flow.response.timestamp_end - flow.response.timestamp_start) if flow.response else None
        
        response_info = {
            'url': flow.request.url,
            'status_code': flow.response.status_code if flow.response else None,
            'response_time': response_time,
            'rating': self._calculate_response_rating(flow)
        }
        
        return response_info

    def _calculate_response_rating(self, flow: http.HTTPFlow) -> int:
        """Calculate response rating (1-5)"""
        if not flow.response:
            return 1
            
        status_code = flow.response.status_code
        if status_code < 300:
            return 5
        elif status_code < 400:
            return 4
        elif status_code < 500:
            return 2
        else:
            return 1

    def done(self):
        """Clean up when proxy is shutting down"""
        try:
            # Close the cache
            if self.cache:
                self.cache.close()
            
            # Save monitoring metrics
            self.monitoring.save_metrics()
            
            # Save any pending model updates
            if hasattr(self.request_model, 'save_training_data'):
                self.request_model.save_training_data()
            
            logger.info("Proxy shutdown completed successfully")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}", exc_info=True)
            self.monitoring.record_error('shutdown_error', str(e))

# Initialize the proxy controller
proxy = ProxyController()

def request(flow: http.HTTPFlow) -> None:
    """mitmproxy request hook"""
    proxy.request(flow)

def response(flow: http.HTTPFlow) -> None:
    """mitmproxy response hook"""
    proxy.response(flow)

def done():
    """mitmproxy shutdown hook"""
    proxy.done()