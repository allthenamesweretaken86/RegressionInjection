# cache.py:
import os
import time
import json
import logging
import shutil
from typing import Dict, List, Tuple, Any, Optional
import hashlib
from urllib.parse import urlparse, parse_qs
from mitmproxy import http
from utils import calculate_time_since_last_request, rate_response
from config import CACHE_DIR, CACHE_EXPIRY_HOURS, MAX_CACHE_SIZE_MB

logger = logging.getLogger(__name__)

class RequestCache:
    def __init__(self):
        """Initialize the cache system"""
        self._init_cache_directory()
        self.cache_size = 0
        self._load_cache_size()
        logger.info("Cache system initialized")

    def _init_cache_directory(self) -> None:
        """Initialize cache directory while preserving existing files"""
        try:
            # Create cache directory if it doesn't exist
            if not os.path.exists(CACHE_DIR):
                os.makedirs(CACHE_DIR)
                self._set_directory_permissions(CACHE_DIR)
                logger.info("Created new cache directory")
            else:
                # Just ensure the directory is writable
                self._ensure_writable(CACHE_DIR)
                logger.info("Using existing cache directory")

        except Exception as e:
            logger.error(f"Error initializing cache directory: {e}")
            raise

    def _ensure_writable(self, path: str) -> None:
        """Ensure the directory is writable using standard Python"""
        try:
            # Try to create a temporary file to test write permissions
            test_file = os.path.join(path, '.write_test')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                logger.debug(f"Verified write access to {path}")
            except Exception as e:
                logger.warning(f"Directory {path} is not writable: {e}")
                self._set_directory_permissions(path)
                
        except Exception as e:
            logger.error(f"Error checking directory permissions: {e}")
    

    def _set_directory_permissions(self, directory: str) -> None:
        """Set appropriate permissions for cache directory"""
        try:
            if os.name == 'nt':  # Windows
                import stat
                # Full control for current user
                os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            else:  # Unix-like
                os.chmod(directory, 0o755)  # rwxr-xr-x
        except Exception as e:
            logger.error(f"Error setting directory permissions: {e}")
            raise

    def _load_cache_size(self) -> None:
        """Calculate current cache size and remove only expired files"""
        try:
            total_size = 0
            current_time = time.time()
            files_to_delete = []

            # Walk through directory tree
            for root, dirs, files in os.walk(CACHE_DIR):
                for name in files:
                    try:
                        file_path = os.path.join(root, name)
                        file_stats = os.stat(file_path)
                        file_age = current_time - file_stats.st_mtime

                        # Only mark for deletion if expired
                        if file_age > (CACHE_EXPIRY_HOURS * 3600):
                            files_to_delete.append(file_path)
                            continue

                        total_size += file_stats.st_size
                    except OSError as e:
                        logger.warning(f"Error accessing cache file {name}: {e}")
                        continue

            # Delete only expired files
            for file_path in files_to_delete:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        logger.debug(f"Removed expired cache file: {file_path}")
                except OSError as e:
                    logger.error(f"Error deleting expired cache file {file_path}: {e}")

            self.cache_size = total_size / (1024 * 1024)  # Convert to MB

            # Only cleanup if we're significantly over the limit
            if self.cache_size > MAX_CACHE_SIZE_MB * 1.1:  # 10% buffer
                self._cleanup_cache()

            logger.info(f"Cache size loaded: {self.cache_size:.2f}MB")

        except Exception as e:
            logger.error(f"Error loading cache size: {e}")
            self.cache_size = 0

    
    def _validate_headers(self, headers: Dict) -> List[Tuple[bytes, bytes]]:
        """Validate and convert headers to bytes"""
        valid_headers = []
        for k, v in headers.items():
            try:
                # Convert key and value to bytes if they aren't already
                key = k.encode('utf-8') if isinstance(k, str) else k
                value = v.encode('utf-8') if isinstance(v, str) else v
                
                # Ensure both are bytes
                if not isinstance(key, bytes) or not isinstance(value, bytes):
                    raise ValueError(f"Header {k} or value {v} could not be converted to bytes")
                    
                valid_headers.append((key, value))
            except Exception as e:
                logger.warning(f"Invalid header {k}: {e}")
                continue
        return valid_headers
    def _load_cache_size(self) -> None:
        """Calculate and load the current cache size"""
        try:
            total_size = 0
            current_time = time.time()
            files_to_delete = []

            for filename in os.listdir(CACHE_DIR):
                file_path = os.path.join(CACHE_DIR, filename)
                try:
                    file_stats = os.stat(file_path)
                    file_age = current_time - file_stats.st_mtime

                    if file_age > (CACHE_EXPIRY_HOURS * 3600):
                        files_to_delete.append(file_path)
                        continue

                    total_size += file_stats.st_size

                except OSError as e:
                    logger.warning(f"Error accessing cache file {filename}: {e}")
                    continue

            # Delete expired files
            for file_path in files_to_delete:
                try:
                    os.remove(file_path)
                    logger.debug(f"Removed expired cache file: {file_path}")
                except OSError as e:
                    logger.error(f"Error deleting expired cache file {file_path}: {e}")

            self.cache_size = total_size / (1024 * 1024)  # Convert to MB

            if self.cache_size > MAX_CACHE_SIZE_MB:
                self._cleanup_cache()

            logger.info(f"Cache size loaded: {self.cache_size:.2f}MB")

        except Exception as e:
            logger.error(f"Error loading cache size: {e}")
            self.cache_size = 0

    def _cleanup_cache(self) -> None:
        """Clean up the cache when it exceeds the maximum size"""
        try:
            cache_files = []
            # Only look at cache files, not directories
            for filename in os.listdir(CACHE_DIR):
                file_path = os.path.join(CACHE_DIR, filename)
                # Skip directories
                if os.path.isdir(file_path):
                    continue
                try:
                    mtime = os.path.getmtime(file_path)
                    size = os.path.getsize(file_path)
                    cache_files.append((file_path, mtime, size))
                except OSError as e:
                    logger.warning(f"Error accessing file {filename}: {e}")
                    continue

            # Sort files by modification time (oldest first)
            cache_files.sort(key=lambda x: x[1])

            # Calculate current cache size (excluding directories)
            current_size = sum(size for _, _, size in cache_files) / (1024 * 1024)  # Convert to MB

            # Remove files until we're under limit
            files_removed = 0
            bytes_removed = 0
            
            for file_path, _, size in cache_files:
                if current_size <= MAX_CACHE_SIZE_MB * 0.9:  # Leave 10% buffer
                    break
                    
                try:
                    # Only remove if it's a file (extra safety check)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        current_size -= size / (1024 * 1024)
                        bytes_removed += size
                        files_removed += 1
                        logger.debug(f"Removed cache file: {file_path}")
                except OSError as e:
                    logger.error(f"Error removing file {file_path}: {e}")
                    continue

            self.cache_size = current_size
            logger.info(
                f"Cache cleanup completed. Removed {files_removed} files "
                f"({bytes_removed / (1024*1024):.2f}MB). New size: {current_size:.2f}MB"
            )

        except Exception as e:
            logger.error(f"Error during cache cleanup: {e}", exc_info=True)

    def handle_request(self, flow: http.HTTPFlow, request_model) -> None:
        """Process the request, retrieve from cache if available, and update cache if needed."""
        try:
            query_params = parse_qs(urlparse(flow.request.url).query)
            force_refresh = query_params.get("force_refresh", ["false"])[0].lower() == "true"

            # Generate cache key
            cache_key = hashlib.md5(flow.request.url.split("?")[0].encode()).hexdigest()
            cache_file = os.path.join(CACHE_DIR, cache_key)

            # Extract all required request features
            request_params = {
                "url": flow.request.url,
                "timestamp": time.time(),
                "user_agent": flow.request.headers.get("User-Agent", ""),
                "public_ip": flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else "",
                "time_since_last_request": calculate_time_since_last_request(flow.request.url),
                "referrer": flow.request.headers.get("Referer", ""),
                "accept_language": flow.request.headers.get("Accept-Language", ""),
                "accept_encoding": flow.request.headers.get("Accept-Encoding", ""),
                "origin": flow.request.headers.get("Origin", ""),
                "content_type": flow.request.headers.get("Content-Type", ""),
                "x_requested_with": flow.request.headers.get("X-Requested-With", ""),
                "connection": flow.request.headers.get("Connection", ""),
                "cookies": flow.request.headers.get("Cookie", ""),
                "x_forwarded_for": flow.request.headers.get("X-Forwarded-For", ""),
                "tls_fingerprint": self._get_tls_fingerprint(flow),
                "http_version": flow.request.http_version,
                "request_method": flow.request.method,
                "cache_control": flow.request.headers.get("Cache-Control", ""),
                "x_custom_headers": self._extract_custom_headers(flow.request.headers),
            }

            # Handle caching based on force_refresh
            if force_refresh:
                flow.request.headers["Cache-Control"] = "no-cache"
                flow.request.headers["Pragma"] = "no-cache"
                flow.request.headers["Surrogate-Control"] = "no-store"
            elif os.path.exists(cache_file) and self._is_cache_valid(cache_file):
                self._serve_cached_response(flow, cache_file)
                return

            # Update the model with request parameters
            request_model.update_model(request_params)

        except Exception as e:
            logger.error(f"Error handling request: {e}", exc_info=True)
            raise

    def _is_cache_valid(self, cache_file: str) -> bool:
        """Check if cache file is valid and not expired"""
        try:
            file_age = time.time() - os.path.getmtime(cache_file)
            return file_age <= (CACHE_EXPIRY_HOURS * 3600)
        except Exception as e:
            logger.error(f"Error checking cache validity: {e}")
            return False

    def _serve_cached_response(self, flow: http.HTTPFlow, cache_file: str) -> None:
        """Serve a response from cache with proper binary handling"""
        try:
            with open(cache_file, 'r') as f:
                cached_response = json.load(f)
            
            # Convert headers to bytes
            headers = []
            for k, v in cached_response["headers"].items():
                try:
                    header_key = k.encode('utf-8') if isinstance(k, str) else k
                    header_value = v.encode('utf-8') if isinstance(v, str) else v
                    headers.append((header_key, header_value))
                except Exception as e:
                    logger.warning(f"Failed to encode header {k}: {e}")
                    continue
            
            # Handle binary content
            if cached_response.get("is_binary", False):
                content = bytes.fromhex(cached_response["content"])
            else:
                content = cached_response["content"].encode('utf-8') if isinstance(cached_response["content"], str) else cached_response["content"]
            
            # Create response
            response = http.Response.make(
                status_code=cached_response["status_code"],
                content=content,
                headers=headers
            )
            
            flow.response = response
            logger.debug(f"Served cached response for: {flow.request.url}")
        except Exception as e:
            logger.error(f"Error serving cached response: {e}", exc_info=True)


    def handle_response(self, flow: http.HTTPFlow, request_model) -> Dict[str, Any]:
        """Process and cache the response."""
        try:
            response_time = (flow.response.timestamp_end - flow.response.timestamp_start) if flow.response else None
            
            # Create response info dictionary
            response_info = {
                "url": flow.request.url,
                "timestamp": time.time(),
                "user_agent": flow.request.headers.get("User-Agent", ""),
                "public_ip": flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else "",
                "time_since_last_request": calculate_time_since_last_request(flow.request.url),
                "referrer": flow.request.headers.get("Referer", ""),
                "accept_language": flow.request.headers.get("Accept-Language", ""),
                "accept_encoding": flow.request.headers.get("Accept-Encoding", ""),
                "origin": flow.request.headers.get("Origin", ""),
                "content_type": flow.request.headers.get("Content-Type", ""),
                "x_requested_with": flow.request.headers.get("X-Requested-With", ""),
                "connection": flow.request.headers.get("Connection", ""),
                "cookies": flow.request.headers.get("Cookie", ""),
                "x_forwarded_for": flow.request.headers.get("X-Forwarded-For", ""),
                "tls_fingerprint": self._get_tls_fingerprint(flow),
                "http_version": flow.request.http_version,
                "request_method": flow.request.method,
                "cache_control": flow.request.headers.get("Cache-Control", ""),
                "x_custom_headers": self._extract_custom_headers(flow.request.headers),
                "response_code": flow.response.status_code if flow.response else None,
                "response_time": response_time,
            }

            # Calculate rating
            if flow.response and flow.response.status_code:
                response_info["rating"] = rate_response(flow.response.status_code)
            else:
                response_info["rating"] = None

            # Update the model with response data
            request_model.update_model(response_info)

            # Cache the response if it's cacheable
            if flow.response and self._is_response_cacheable(flow):
                cache_key = hashlib.md5(flow.request.url.split("?")[0].encode()).hexdigest()
                cache_file = os.path.join(CACHE_DIR, cache_key)
                self._cache_response(flow, cache_file)

            return response_info

        except Exception as e:
            logger.error(f"Error handling response: {e}", exc_info=True)
            # Return a minimal response info with error details
            return {
                "url": getattr(flow.request, "url", "unknown"),
                "error": str(e),
                "rating": 4  # Error rating
            }

    def _get_tls_fingerprint(self, flow: http.HTTPFlow) -> str:
        """Extract TLS fingerprint from the connection"""
        try:
            if flow.client_conn and flow.client_conn.tls_version:
                return f"{flow.client_conn.tls_version}:{flow.client_conn.cipher_name}"
            return ""
        except Exception:
            return ""

    def _extract_custom_headers(self, headers) -> str:
        """Extract and format custom headers (X- headers)"""
        try:
            custom_headers = {k: v for k, v in headers.items() if k.startswith('X-') 
                            and k not in ['X-Requested-With', 'X-Forwarded-For']}
            return json.dumps(custom_headers) if custom_headers else ""
        except Exception:
            return ""

    def _is_response_cacheable(self, flow: http.HTTPFlow) -> bool:
        """Check if response should be cached"""
        try:
            if not flow.response:
                return False
                
            if flow.response.status_code >= 400:
                return False

            cache_control = flow.response.headers.get("Cache-Control", "").lower()
            if "no-store" in cache_control or "no-cache" in cache_control:
                return False

            if flow.request.method not in ["GET", "HEAD"]:
                return False

            return True
        except Exception:
            return False

    def _cache_response(self, flow: http.HTTPFlow, cache_file: str) -> None:
        """Cache the response data, preserving existing cache if valid"""
        try:
            # Check if we already have a valid cache file
            if os.path.exists(cache_file) and self._is_cache_valid(cache_file):
                logger.debug(f"Valid cache exists for: {flow.request.url}")
                return

            # Convert headers to a dict
            headers_dict = {}
            for k, v in flow.response.headers.items():
                try:
                    key = k.decode('utf-8') if isinstance(k, bytes) else str(k)
                    value = v.decode('utf-8') if isinstance(v, bytes) else str(v)
                    headers_dict[key] = value
                except Exception as e:
                    logger.warning(f"Failed to decode header {k}: {e}")
                    continue
            
            # Handle content based on type
            content = flow.response.content
            is_binary = 'image' in flow.response.headers.get('content-type', '').lower()
            
            cache_data = {
                "status_code": flow.response.status_code,
                "content_type": flow.response.headers.get('content-type', ''),
                "is_binary": is_binary,
                "content": content.hex() if is_binary else content.decode('utf-8', errors='replace'),
                "headers": headers_dict,
                "timestamp": time.time()
            }
            
            # Write to cache file
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)
                
            # Update cache size
            self.cache_size += os.path.getsize(cache_file) / (1024 * 1024)
            
            # Check if cleanup is needed
            if self.cache_size > MAX_CACHE_SIZE_MB:
                self._cleanup_cache()
                
            logger.debug(f"Cached response for: {flow.request.url}")
                
        except Exception as e:
            logger.error(f"Error caching response: {e}", exc_info=True)
