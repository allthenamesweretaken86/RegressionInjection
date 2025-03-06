from mitmproxy import websocket, ctx, http
from bs4 import BeautifulSoup
import pandas as pd
import pickle
import os
import datetime
import json
import time
PICKLE_FILE = "./pickles/data.pickle"
MAX_ROWS_PER_APPEND = 100
# Cache variables for alert.js content and last modification time
cached_js_content = ""
last_mod_time = 0
CACHE_CHECK_INTERVAL = 2  # in seconds

# Global variables to cache the contents and last modification times
cached_js_content = ""
last_js_mod_time = 0
cached_json_data = {}
last_json_mod_time = 0
# Global DataFrame to track rows between saves
current_df = pd.DataFrame()

def serialize_cookies(cookies):
    """
    Converts cookie dictionary to JSON string for storage.
    """
    try:
        # Filter out None values and convert to string representation
        cleaned_cookies = {k: str(v) for k, v in cookies.items() if v is not None}
        return json.dumps(cleaned_cookies)
    except Exception as e:
        ctx.log.error(f"Error serializing cookies: {e}")
        return "{}"

def collect_request_response_params(flow: http.HTTPFlow):
    """Collects all request and response parameters."""
    params = {}
    if hasattr(flow, 'request'):
        params.update(dict(flow.request.query))
        params.update({f"req_header_{k}": v for k, v in flow.request.headers.items()})
    if hasattr(flow, 'response'):
        params["response_content_type"] = flow.response.headers.get("content-type")
        params["response_content_length"] = flow.response.headers.get("content-length")
        params.update({f"resp_header_{k}": v for k, v in flow.response.headers.items()})
    return params

def decode_if_bytes(value):
    """Helper function to decode bytes to string if necessary."""
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return value.decode('latin-1')
    return str(value)

def collect_request_cookies(flow: http.HTTPFlow):
    """Collects all cookies from the request."""
    cookies = {}
    if hasattr(flow.request, 'cookies'):
        try:
            # Handle cookies directly from the request.cookies object
            for name, value in flow.request.cookies.items():
                name = decode_if_bytes(name)
                value = decode_if_bytes(value)
                cookies[name] = value
                #ctx.log.info(f"Collected request cookie: {name}={value}")
        except Exception as e:
            ctx.log.error(f"Error processing request cookies: {e}")
    return cookies

def collect_response_cookies(flow: http.HTTPFlow):
    """Collects all cookies from the response."""
    cookies = {}
    if hasattr(flow, 'response') and hasattr(flow.response, 'cookies'):
        try:
            # Handle cookies directly from the response.cookies object
            for name, (value, attrs) in flow.response.cookies.items():
                name = decode_if_bytes(name)
                value = decode_if_bytes(value)
                cookies[name] = value
                ctx.log.info(f"Collected response cookie: {name}={value}")
        except Exception as e:
            ctx.log.error(f"Error processing response cookies: {e}")
    return cookies

def load_data():
    """Loads the DataFrame from the pickle file if it exists, otherwise creates a new one."""
    if os.path.exists(PICKLE_FILE):
        try:
            with open(PICKLE_FILE, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            ctx.log.error(f"Error loading pickle file: {e}")
            return pd.DataFrame()
    return pd.DataFrame()

def append_data(data):
    """Appends data to the global DataFrame and saves to pickle file when threshold is reached."""
    global current_df
    
    try:
        # Convert cookie dictionaries to JSON strings
        if 'req_cookie' in data:
            data['req_cookie'] = serialize_cookies(data['req_cookie'])
        if 'resp_cookie' in data:
            data['resp_cookie'] = serialize_cookies(data['resp_cookie'])
        
        # Append new data to current DataFrame
        current_df = pd.concat([current_df, pd.DataFrame(data, index=[0])], ignore_index=True)
        
        # Check if we've reached the threshold for saving
        if len(current_df) >= MAX_ROWS_PER_APPEND:
            save_data()
            
    except Exception as e:
        ctx.log.error(f"Error in append_data: {e}")

def save_data():
    """Saves the current DataFrame to the pickle file."""
    global current_df
    
    try:
        # Load existing data
        existing_df = load_data()
        
        # Combine with current data
        combined_df = pd.concat([existing_df, current_df], ignore_index=True)
        
        # Save the combined DataFrame
        os.makedirs(os.path.dirname(PICKLE_FILE), exist_ok=True)
        with open(PICKLE_FILE, "wb") as f:
            pickle.dump(combined_df, f)
            
        ctx.log.info(f"Saved {len(current_df)} rows to pickle file. Total rows: {len(combined_df)}")
        
        # Reset the current DataFrame
        current_df = pd.DataFrame()
        
    except Exception as e:
        ctx.log.error(f"Error saving to pickle file: {e}")

def request(flow: http.HTTPFlow) -> None:
    headers_to_remove = [
        'if-modified-since',
        'if-none-match',
        'cache-control',
        'pragma'
    ]
    
    for header in headers_to_remove:
        if header in flow.request.headers:
            del flow.request.headers[header]
    
    # Add caching headers
    flow.request.headers["Cache-Control"] = "public, max-age=86400, s-maxage=86400"
    flow.request.headers["Expires"] = (
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).strftime("%a, %d %b %Y %H:%M:%S GMT")
    flow.request.headers["User-Agent"] = "Mozilla/5.0 (Generic Browser)"
    flow.request.headers["Pragma"] = "cache"
    
    if "Vary" in flow.request.headers:
        del flow.request.headers["Vary"]




def get_latest_js_content(path):
    global cached_js_content, last_js_mod_time
    ctx.js_script = path
    # Ensure the path to alert.js is set
    if not hasattr(ctx, 'js_script'):
       

    # Add logging to check the path and modification time
        ctx.log.info(f"Checking for updates in {path}")

        try:
            mod_time = os.path.getmtime(ctx.js_script)  # Check for modification

            if mod_time != last_js_mod_time:  # Reload if modified
                with open(ctx.js_script, 'r', encoding='utf-8') as f:
                    cached_js_content = f.read()
                last_js_mod_time = mod_time
                ctx.log.info("Reloaded updated JavaScript from {path}")
        except Exception as e:
            ctx.log.error(f"Error reading {ctx.js_script}: {e}")

        return cached_js_content

def get_latest_json_content(path):
    global cached_json_data, last_json_mod_time

    # Ensure the path to the JSON file is set
    file_path = path  # Adjust the path as needed

    # Add logging to check the path and modification time
    ctx.log.info(f"Checking for updates in {file_path}")

    try:
        mod_time = os.path.getmtime(file_path)  # Check for modification

        if mod_time != last_json_mod_time:  # Reload if modified
            with open(file_path, 'r', encoding='utf-8') as f:
                cached_json_data = json.load(f)
            last_json_mod_time = mod_time
            ctx.log.info("Reloaded updated JSON from {file_path}")
    except Exception as e:
        ctx.log.error(f"Error reading {json_file_path}: {e}")

    return cached_json_data

def response(flow: http.HTTPFlow) -> None:
    if 'WebSocket' in flow.response.text:
        return

    try:
        # --- Collect Request and Response Parameters ---
        params = collect_request_response_params(flow)

        # --- Collect Cookies ---
        req_cookies = collect_request_cookies(flow)
        resp_cookies = collect_response_cookies(flow)

        # Create data dictionary
        data = {
            "request_url": flow.request.url,
            "request_method": flow.request.method,
            "req_cookie": req_cookies,
            "resp_cookie": resp_cookies,
            "response_status_code": getattr(flow.response, 'status_code', None),
            "failed": 1 if getattr(flow.response, 'status_code', 200) >= 400 else 0,
            "timestamp": datetime.datetime.now().isoformat(),  # Add timestamp
            **params
        }
        # Append data to the DataFrame
        append_data(data)

        # Only inject JavaScript if it's an HTML response
        if 'text/html' in flow.response.headers.get('content-type', '').lower():
            modified_html = js_inject(flow.response.text)
            flow.response.text = modified_html
        
        # Add CORS headers to the response
        flow.response.headers["Access-Control-Allow-Origin"] = "*"
        flow.response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        flow.response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

    except Exception as e:
        ctx.log.error(f"Error in response handler: {str(e)}")

def js_inject(html):
    try:
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(html, features="html.parser")
        if soup.body:
            # Insert CDN script
            cdn = soup.new_tag("script", type="text/javascript", 
                               src="//cdnjs.cloudflare.com/ajax/libs/socket.io/1.3.6/socket.io.min.js")
            soup.body.insert(0, cdn)

            # Insert custom script
            script = soup.new_tag("script", type="application/javascript")
            js_content = get_latest_js_content('./js/alert.js')  # Get the latest content
            jsonData = get_latest_json_content('./js/json')

            # Construct the full JavaScript content including jsonData
            # Ensure that jsonData is formatted correctly for JavaScript
            json_variable_assignment = f"const jsonData = {json.dumps(jsonData)};"
            script_content = f'''
            {json_variable_assignment}
            {js_content}
            '''
            script.string = script_content
            soup.body.insert(1, script)

            ctx.log.info("Injected JavaScript with jsonData and alert.js content")
            time.sleep(10000)

            # Return the modified HTML
            return str(soup)
    except Exception as e:
        ctx.log.error(f"Error in js_inject: {e}")
        return html

def read_file(filename):
    with open(filename) as f:
        return f.read()


def log(msg):
    ctx.log.info(msg)