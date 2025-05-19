from mitmproxy import ctx, http # Removed websocket as it's not used here
from bs4 import BeautifulSoup
import pandas as pd # Keep if used for other data collection not related to main proxy logic
import pickle
import os
import datetime # Corrected from 'datettime'
import json
import time # Keep for general timing if needed, but removed the long sleep

# This script (inject_script.py) seems to be for a different purpose than the core proxy logic
# The data collection here (PICKLE_FILE, append_data, etc.) appears separate from
# the main training data pipeline in request_features.py and model.py.
# If this is intended to be part of the same system, it needs integration.
# For now, I'm only fixing the critical sleep and logging.

PICKLE_FILE = "./pickles/inject_script_data.pickle" # Renamed to avoid conflict
MAX_ROWS_PER_APPEND = 100
# Cache variables for alert.js content and last modification time
cached_js_content = ""
last_js_mod_time = 0 # Corrected variable name
cached_json_data = {} # Assuming this is for some JSON data to be injected
last_json_mod_time = 0 # Corrected variable name

CACHE_CHECK_INTERVAL = 2  # in seconds

# Global DataFrame to track rows between saves for this script's specific data
current_df_inject = pd.DataFrame() # Renamed to avoid conflict

logger = logging.getLogger("RegressionInjection.InjectScript") # Use the main logger

def serialize_cookies(cookies):
    try:
        cleaned_cookies = {str(k): str(v) for k, v in cookies.items() if v is not None}
        return json.dumps(cleaned_cookies)
    except Exception as e:
        logger.error(f"Error serializing cookies: {e}")
        return "{}"

# ... (rest of the functions like collect_request_response_params, decode_if_bytes, etc. from the original file)
# For brevity, I'm not repeating them all if they are unchanged in logic, but they should be here.
# Assume they are present from the original.

def collect_request_response_params(flow: http.HTTPFlow):
    """Collects all request and response parameters."""
    params = {}
    if hasattr(flow, 'request'):
        # flow.request.query is a MultiDictView which behaves like a dict for items()
        params.update(dict(flow.request.query.items())) 
        params.update({f"req_header_{k.decode('utf-8','ignore')}": v.decode('utf-8','ignore') for k, v in flow.request.headers.fields})
    if hasattr(flow, 'response') and flow.response:
        params["response_content_type"] = flow.response.headers.get("content-type", "")
        params["response_content_length"] = flow.response.headers.get("content-length", "")
        params.update({f"resp_header_{k.decode('utf-8','ignore')}": v.decode('utf-8','ignore') for k, v in flow.response.headers.fields})
    return params

def decode_if_bytes(value):
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return value.decode('latin-1', errors='replace') # Added error handling
    return str(value)

def collect_request_cookies(flow: http.HTTPFlow):
    cookies = {}
    if hasattr(flow.request, 'cookies') and flow.request.cookies:
        try:
            for name, value in flow.request.cookies.items(multi=True): # Use items(multi=True) for all values
                name = decode_if_bytes(name)
                value = decode_if_bytes(value)
                if name in cookies: # Handle multiple cookies with the same name
                    if isinstance(cookies[name], list):
                        cookies[name].append(value)
                    else:
                        cookies[name] = [cookies[name], value]
                else:
                    cookies[name] = value
        except Exception as e:
            logger.error(f"Error processing request cookies: {e}")
    return cookies

def collect_response_cookies(flow: http.HTTPFlow):
    cookies = {}
    if hasattr(flow, 'response') and flow.response and hasattr(flow.response, 'cookies') and flow.response.cookies:
        try:
            for name, (value, attrs) in flow.response.cookies.items(multi=True):
                name = decode_if_bytes(name)
                value = decode_if_bytes(value)
                # Store only the value, or value+attrs if needed
                if name in cookies:
                     if isinstance(cookies[name], list):
                        cookies[name].append(value)
                     else:
                        cookies[name] = [cookies[name], value]
                else:
                    cookies[name] = value
                logger.debug(f"Collected response cookie: {name}={value}")
        except Exception as e:
            logger.error(f"Error processing response cookies: {e}")
    return cookies


def load_data_inject(): # Renamed
    if os.path.exists(PICKLE_FILE):
        try:
            with open(PICKLE_FILE, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            logger.error(f"Error loading inject script pickle file: {e}")
    return pd.DataFrame()

def append_data_inject(data): # Renamed
    global current_df_inject
    try:
        if 'req_cookie' in data: data['req_cookie'] = serialize_cookies(data['req_cookie'])
        if 'resp_cookie' in data: data['resp_cookie'] = serialize_cookies(data['resp_cookie'])
        
        current_df_inject = pd.concat([current_df_inject, pd.DataFrame(data, index=[0])], ignore_index=True)
        
        if len(current_df_inject) >= MAX_ROWS_PER_APPEND:
            save_data_inject()
    except Exception as e:
        logger.error(f"Error in append_data_inject: {e}")

def save_data_inject(): # Renamed
    global current_df_inject
    try:
        existing_df = load_data_inject()
        combined_df = pd.concat([existing_df, current_df_inject], ignore_index=True)
        os.makedirs(os.path.dirname(PICKLE_FILE), exist_ok=True)
        with open(PICKLE_FILE, "wb") as f:
            pickle.dump(combined_df, f)
        logger.info(f"Saved {len(current_df_inject)} rows to inject_script_data.pickle. Total rows: {len(combined_df)}")
        current_df_inject = pd.DataFrame()
    except Exception as e:
        logger.error(f"Error saving to inject_script_data.pickle: {e}")


def request(flow: http.HTTPFlow) -> None:
    # This request modification logic might conflict with the main proxy's goals
    # or the RetryManager's optimization. Consider if this is still desired.
    # For now, keeping it as it was, but with logging.
    logger.debug(f"inject_script.py: Modifying request headers for {flow.request.url}")
    headers_to_remove = ['if-modified-since', 'if-none-match', 'cache-control', 'pragma']
    for header in headers_to_remove:
        if header in flow.request.headers:
            del flow.request.headers[header]
    
    flow.request.headers["Cache-Control"] = "public, max-age=86400, s-maxage=86400" # Aggressive caching
    flow.request.headers["Expires"] = (datetime.datetime.utcnow() + datetime.timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    flow.request.headers["User-Agent"] = "Mozilla/5.0 (Generic Browser)" # This overrides any optimized UA
    flow.request.headers["Pragma"] = "cache"
    if "Vary" in flow.request.headers: del flow.request.headers["Vary"]


def get_latest_js_content(path):
    global cached_js_content, last_js_mod_time # Corrected variable name
    # Removed ctx.js_script = path, as ctx might not be available globally here
    # and path is passed as an argument.
    
    current_time = time.time()
    # Check cache interval to avoid too frequent file reads
    if current_time - getattr(get_latest_js_content, 'last_check_time', 0) < CACHE_CHECK_INTERVAL:
        return cached_js_content
    get_latest_js_content.last_check_time = current_time

    try:
        if not os.path.exists(path):
            logger.error(f"JavaScript file not found at {path}")
            return "" # Return empty if not found
        mod_time = os.path.getmtime(path)
        if mod_time != last_js_mod_time:
            with open(path, 'r', encoding='utf-8') as f:
                cached_js_content = f.read()
            last_js_mod_time = mod_time
            logger.info(f"Reloaded updated JavaScript from {path}") # Fixed logging string
    except Exception as e:
        logger.error(f"Error reading JavaScript file {path}: {e}")
    return cached_js_content

def get_latest_json_content(path): # Similar fixes as get_latest_js_content
    global cached_json_data, last_json_mod_time # Corrected variable name

    current_time = time.time()
    if current_time - getattr(get_latest_json_content, 'last_check_time', 0) < CACHE_CHECK_INTERVAL:
        return cached_json_data
    get_latest_json_content.last_check_time = current_time

    try:
        if not os.path.exists(path):
            logger.error(f"JSON file not found at {path}")
            return {}
        mod_time = os.path.getmtime(path)
        if mod_time != last_json_mod_time:
            with open(path, 'r', encoding='utf-8') as f:
                cached_json_data = json.load(f)
            last_json_mod_time = mod_time
            logger.info(f"Reloaded updated JSON from {path}") # Fixed logging string
    except Exception as e:
        logger.error(f"Error reading JSON file {path}: {e}")
    return cached_json_data

def response(flow: http.HTTPFlow) -> None:
    # This response handler collects data separately from the main proxy logic.
    # And injects JS.
    if flow.response and 'WebSocket' in flow.response.text: # Check if flow.response exists
        return

    try:
        params = collect_request_response_params(flow)
        req_cookies = collect_request_cookies(flow)
        resp_cookies = collect_response_cookies(flow)

        data_for_inject_pickle = {
            "request_url": flow.request.url,
            "request_method": flow.request.method,
            "req_cookie": req_cookies, # Will be serialized
            "resp_cookie": resp_cookies, # Will be serialized
            "response_status_code": getattr(flow.response, 'status_code', None),
            "failed": 1 if getattr(flow.response, 'status_code', 200) >= 400 else 0,
            "timestamp": datetime.datetime.now().isoformat(),
            **params
        }
        append_data_inject(data_for_inject_pickle)

        if flow.response and 'text/html' in flow.response.headers.get('content-type', '').lower():
            # Ensure response.text is used carefully; it decodes content.
            # If content is already decoded, use that. If not, flow.response.text will decode it.
            html_content = flow.response.text # This decodes based on headers/charset sniffing
            modified_html = js_inject(html_content)
            flow.response.text = modified_html # This re-encodes if necessary
        
        if flow.response: # Add CORS headers only if there's a response
            flow.response.headers["Access-Control-Allow-Origin"] = "*"
            flow.response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS" # OPTIONS for preflight
            flow.response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

    except Exception as e:
        logger.error(f"Error in inject_script.py response handler: {e}", exc_info=True)


def js_inject(html_text: str) -> str: # Type hint for clarity
    try:
        soup = BeautifulSoup(html_text, "html.parser") # Changed features to html.parser (lxml is faster if available)
        if soup.body:
            cdn_script = soup.new_tag("script", type="text/javascript", src="//cdnjs.cloudflare.com/ajax/libs/socket.io/1.3.6/socket.io.min.js")
            soup.body.insert(0, cdn_script)

            custom_script_tag = soup.new_tag("script", type="application/javascript")
            
            # Paths for JS and JSON files need to be correct relative to where mitmproxy runs
            # or absolute. Using './js/' implies a 'js' folder in the current working directory of mitmproxy.
            js_file_path = './js/alert.js' 
            json_file_path = './js/data.json' # Example path, ensure this file exists

            latest_js = get_latest_js_content(js_file_path)
            latest_json_data = get_latest_json_content(json_file_path) # Make sure this path is correct

            json_assignment = f"const injectedJsonData = {json.dumps(latest_json_data)};"
            
            # Removed the long time.sleep(10000)
            custom_script_tag.string = f"\n{json_assignment}\n{latest_js}\n"
            soup.body.insert(1, custom_script_tag)
            logger.info("JavaScript injected with jsonData and alert.js content.")
            return str(soup)
        else:
            logger.warning("No <body> tag found in HTML, cannot inject JavaScript.")
            return html_text
    except Exception as e:
        logger.error(f"Error in js_inject: {e}", exc_info=True)
        return html_text # Return original HTML on error


# This script, if used as a mitmproxy addon (-s inject_script.py), would run its own
# request/response handlers. If it's meant to be utility functions for main.py,
# then main.py should call its functions directly.
# For now, assuming it can be run as a separate addon or its functions are called.
# If it's an addon, it needs the `addons` list like in main.py:
# addons = [sys.modules[__name__]] # Or a class instance