from flask import Flask, render_template, request, jsonify, send_from_directory
import json
import os
import logging
import sys
import time
import subprocess
import threading
import pandas as pd
from urllib.parse import urlparse
import requests # For downloading blocklist

# --- Configuration Import ---
try:
    import config # Import the config module itself
    from config import (
        HTML_RATING_KEYWORDS_FILE, LOG_FILE,
        MANAGEMENT_SERVER_HOST, MANAGEMENT_SERVER_PORT,
        MITMPROXY_CERT_DIR, MITMPROXY_CA_CERT_FILENAME,
        MITMPROXY_LISTEN_HOST, MITMPROXY_LISTEN_PORT,
        MITMPROXY_MAIN_SCRIPT,
        RATING_SCALE_MIN, RATING_SCALE_MAX,
        TRAINING_DATA_FILE,
        DNS_BLOCKLIST_URL, LOCAL_DNS_BLOCKLIST_FILE # Added blocklist configs
    )
except ImportError:
    print("FATAL ERROR: config.py not found or missing critical variables.")
    sys.exit(1)

# --- Utils Import ---
try:
    import utils # Import the utils module itself
    from utils import (
        load_html_keywords, update_html_keywords as util_update_keywords,
        get_html_keywords as util_get_keywords,
        # Blocklist functions from utils will be used as utils.function_name
    )
except ImportError:
    print("FATAL ERROR: utils.py not found or missing critical functions (HTML keywords or Blocklist).")
    sys.exit(1)

app = Flask(__name__)
app.secret_key = os.urandom(24)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s')
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.INFO)
app.logger.setLevel(logging.DEBUG)

mitmproxy_process = None
mitmproxy_output_lines = []
mitmproxy_output_lock = threading.Lock()

MITMPROXY_COMMAND = [
    "mitmdump",
    "-s", MITMPROXY_MAIN_SCRIPT,
    "--listen-host", MITMPROXY_LISTEN_HOST,
    "--listen-port", str(MITMPROXY_LISTEN_PORT),
    "--set", f"confdir={MITMPROXY_CERT_DIR}",
    "--set", "block_global=false",
]

MAX_LOG_ENTRIES_UI = 300
proxy_ui_log_entries = []
ui_log_lock = threading.Lock()

CA_CERT_PATH = os.path.join(MITMPROXY_CERT_DIR, MITMPROXY_CA_CERT_FILENAME)

# --- DNS Blocklist State ---
dns_blocklist_data = set() # In-memory set of blocked domains
blocklist_lock = threading.Lock() # Lock for modifying the list file and set

def initialize_blocklist():
    """Downloads (if necessary) and loads the DNS blocklist."""
    global dns_blocklist_data
    try:
        # Attempt to download the latest blocklist
        # This can be slow, consider doing it in a thread if it blocks startup too long
        app.logger.info(f"Attempting to download DNS blocklist from {config.DNS_BLOCKLIST_URL}...")
        utils.download_blocklist(config.DNS_BLOCKLIST_URL, config.LOCAL_DNS_BLOCKLIST_FILE)

        with blocklist_lock:
            dns_blocklist_data = utils.load_blocklist(config.LOCAL_DNS_BLOCKLIST_FILE)
        app.logger.info(f"DNS blocklist initialized/updated. Loaded {len(dns_blocklist_data)} entries from {config.LOCAL_DNS_BLOCKLIST_FILE}.")
        add_ui_log_entry("info", f"DNS blocklist loaded with {len(dns_blocklist_data)} domains.", "blocklist_init")

    except requests.exceptions.RequestException as re:
        app.logger.error(f"Failed to download DNS blocklist from URL: {re}. Will try to load local copy.")
        add_ui_log_entry("error", f"Failed to download blocklist: {re}. Using local if available.", "blocklist_init")
        # Try to load local if download failed
        if os.path.exists(config.LOCAL_DNS_BLOCKLIST_FILE):
            with blocklist_lock:
                 dns_blocklist_data = utils.load_blocklist(config.LOCAL_DNS_BLOCKLIST_FILE)
            app.logger.info(f"Loaded {len(dns_blocklist_data)} entries from local DNS blocklist: {config.LOCAL_DNS_BLOCKLIST_FILE}.")
            add_ui_log_entry("info", f"Loaded local blocklist: {len(dns_blocklist_data)} domains.", "blocklist_init")
        else:
            app.logger.warning(f"Local DNS blocklist file also not found: {config.LOCAL_DNS_BLOCKLIST_FILE}. No DNS blocking active.")
            add_ui_log_entry("warning", "No local blocklist found. DNS blocking inactive.", "blocklist_init")
    except Exception as e:
        app.logger.error(f"Failed to initialize DNS blocklist: {e}", exc_info=True)
        add_ui_log_entry("error", f"General error initializing blocklist: {e}", "blocklist_init")


def add_ui_log_entry(log_type, message, source="management_ui", details=None):
    with ui_log_lock:
        entry = {
            "timestamp": time.time(), "type": log_type, "message": message,
            "source": source, "details": details or {}
        }
        proxy_ui_log_entries.insert(0, entry)
        if len(proxy_ui_log_entries) > MAX_LOG_ENTRIES_UI:
            proxy_ui_log_entries.pop()
        app.logger.debug(f"UI Log ({source} - {log_type}): {message[:100]}")

def capture_mitmproxy_output(pipe, stream_name="stdout"):
    # ... (same as your original code)
    global mitmproxy_output_lines
    try:
        for line_bytes in iter(pipe.readline, b''):
            line = line_bytes.decode('utf-8', errors='replace').strip()
            if line:
                add_ui_log_entry("mitmproxy_console", line, source=f"mitmproxy_process ({stream_name})")
                with mitmproxy_output_lock:
                    mitmproxy_output_lines.append(line)
                    if len(mitmproxy_output_lines) > 50:
                        mitmproxy_output_lines.pop(0)
    except Exception as e:
        error_msg = f"Error reading mitmproxy {stream_name}: {e}"
        app.logger.error(error_msg)
        add_ui_log_entry("error", error_msg, source="mitmproxy_process_reader")
    finally:
        pipe.close()
        shutdown_msg = f"Mitmproxy {stream_name} stream closed."
        app.logger.info(shutdown_msg)
        add_ui_log_entry("system", shutdown_msg, source="mitmproxy_process_reader")

@app.route('/')
def index():
    current_keywords = util_get_keywords()
    ca_cert_exists = os.path.exists(CA_CERT_PATH)
    mitmproxy_status_text = "Stopped"
    global mitmproxy_process
    if mitmproxy_process and mitmproxy_process.poll() is None:
        mitmproxy_status_text = "Running"

    if not ca_cert_exists and mitmproxy_status_text == "Stopped":
         add_ui_log_entry("warning",
                          f"CA certificate '{MITMPROXY_CA_CERT_FILENAME}' not found in '{MITMPROXY_CERT_DIR}'. "
                          "Please start the proxy using the button above. Mitmproxy should generate the certificate on its first run.",
                          source="system_check")

    return render_template('index.html',
                           keywords=current_keywords,
                           ca_cert_exists=ca_cert_exists,
                           ca_cert_filename=MITMPROXY_CA_CERT_FILENAME,
                           mitmproxy_host=MITMPROXY_LISTEN_HOST,
                           mitmproxy_port=MITMPROXY_LISTEN_PORT,
                           mitmproxy_status=mitmproxy_status_text,
                           MAX_LOG_ENTRIES_UI=MAX_LOG_ENTRIES_UI,
                           MITMPROXY_CERT_DIR=MITMPROXY_CERT_DIR,
                           RATING_SCALE_MIN=RATING_SCALE_MIN,
                           RATING_SCALE_MAX=RATING_SCALE_MAX,
                           dns_blocklist_count=len(dns_blocklist_data) # Pass count to template
                           )

# --- Mitmproxy Control & Certificate Download APIs ---
# ... (Keep your existing /download-ca-certificate, /api/mitmproxy/* routes as they are) ...
@app.route('/download-ca-certificate')
def download_ca_certificate():
    try:
        if not os.path.exists(CA_CERT_PATH):
            app.logger.error(f"CA Certificate file not found at {CA_CERT_PATH}")
            add_ui_log_entry("error", f"Download attempt failed: CA cert file not found at {CA_CERT_PATH}", source="certificate_download")
            return "Error: CA Certificate file not found. Start mitmproxy to generate it.", 404
        add_ui_log_entry("info", f"CA certificate '{MITMPROXY_CA_CERT_FILENAME}' downloaded.", source="certificate_download")
        return send_from_directory(MITMPROXY_CERT_DIR, MITMPROXY_CA_CERT_FILENAME,
                                   as_attachment=True, mimetype='application/x-pem-file')
    except Exception as e:
        app.logger.error(f"Error serving CA certificate: {e}", exc_info=True)
        add_ui_log_entry("error", f"Server error serving CA certificate: {e}", source="certificate_download")
        return "Error serving CA certificate.", 500

@app.route('/api/mitmproxy/start', methods=['POST'])
def start_mitmproxy_api():
    global mitmproxy_process, mitmproxy_output_lines
    if mitmproxy_process and mitmproxy_process.poll() is None:
        add_ui_log_entry("warning", "Mitmproxy is already running.", source="mitmproxy_control")
        return jsonify({"status": "warning", "message": "Mitmproxy is already running."})
    try:
        # ... (rest of your start_mitmproxy_api logic)
        if not os.path.exists(MITMPROXY_CERT_DIR):
            try:
                os.makedirs(MITMPROXY_CERT_DIR, exist_ok=True)
                add_ui_log_entry("info", f"Created mitmproxy certificate directory: {MITMPROXY_CERT_DIR}", source="mitmproxy_control")
            except OSError as e:
                msg = f"Failed to create mitmproxy cert dir '{MITMPROXY_CERT_DIR}': {e}."
                add_ui_log_entry("error", msg, source="mitmproxy_control")
                return jsonify({"status": "error", "message": msg}), 500
        if not os.path.exists(MITMPROXY_MAIN_SCRIPT):
            msg = f"Mitmproxy main script '{MITMPROXY_MAIN_SCRIPT}' not found."
            add_ui_log_entry("error", msg, source="mitmproxy_control")
            return jsonify({"status": "error", "message": msg}), 500

        app.logger.info(f"Starting mitmproxy: {' '.join(MITMPROXY_COMMAND)}")
        add_ui_log_entry("info", f"Executing: {' '.join(MITMPROXY_COMMAND)}", source="mitmproxy_control")
        with mitmproxy_output_lock: mitmproxy_output_lines.clear()
        mitmproxy_process = subprocess.Popen(MITMPROXY_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        threading.Thread(target=capture_mitmproxy_output, args=(mitmproxy_process.stdout,"stdout"), daemon=True).start()
        threading.Thread(target=capture_mitmproxy_output, args=(mitmproxy_process.stderr,"stderr"), daemon=True).start()
        time.sleep(2)
        if mitmproxy_process.poll() is None:
            msg = f"Mitmproxy started (PID: {mitmproxy_process.pid})."
            add_ui_log_entry("success", msg, source="mitmproxy_control")
            return jsonify({"status": "success", "message": "Mitmproxy started."})
        else:
            exit_code = mitmproxy_process.returncode
            error_summary = f"Mitmproxy failed/exited (Code: {exit_code}). "
            with mitmproxy_output_lock:
                 if mitmproxy_output_lines: error_summary += "Last output: " + " | ".join(mitmproxy_output_lines[-3:])
            add_ui_log_entry("error", error_summary, source="mitmproxy_control")
            mitmproxy_process = None
            return jsonify({"status": "error", "message": f"Mitmproxy failed (Code: {exit_code}). Check logs."}), 500
    except Exception as e:
        app.logger.error(f"Error starting mitmproxy: {e}", exc_info=True)
        add_ui_log_entry("error", f"Exception starting mitmproxy: {e}", source="mitmproxy_control")
        return jsonify({"status": "error", "message": f"Failed to start mitmproxy: {str(e)}"}), 500


@app.route('/api/mitmproxy/stop', methods=['POST'])
def stop_mitmproxy_api():
    global mitmproxy_process
    # ... (rest of your stop_mitmproxy_api logic)
    if mitmproxy_process and mitmproxy_process.poll() is None:
        try:
            pid = mitmproxy_process.pid
            app.logger.info(f"Stopping mitmproxy (PID: {pid})...")
            add_ui_log_entry("info", f"Attempting to stop mitmproxy (PID: {pid})...", source="mitmproxy_control")
            mitmproxy_process.terminate()
            try:
                mitmproxy_process.wait(timeout=5)
                add_ui_log_entry("success", f"Mitmproxy (PID: {pid}) terminated.", source="mitmproxy_control")
            except subprocess.TimeoutExpired:
                app.logger.warning(f"Mitmproxy (PID: {pid}) did not terminate gracefully, sending SIGKILL.")
                add_ui_log_entry("warning", f"Mitmproxy (PID: {pid}) timeout, forcing kill.", source="mitmproxy_control")
                mitmproxy_process.kill(); mitmproxy_process.wait(timeout=2)
                add_ui_log_entry("success", f"Mitmproxy (PID: {pid}) killed.", source="mitmproxy_control")
            mitmproxy_process = None
            return jsonify({"status": "success", "message": "Mitmproxy stopped."})
        except Exception as e:
            app.logger.error(f"Error stopping mitmproxy: {e}", exc_info=True)
            add_ui_log_entry("error", f"Exception stopping mitmproxy: {e}", source="mitmproxy_control")
            if mitmproxy_process and mitmproxy_process.poll() is None:
                 try: mitmproxy_process.kill()
                 except: pass
            mitmproxy_process = None # Ensure it's cleared
            return jsonify({"status": "error", "message": f"Error stopping mitmproxy: {str(e)}"}), 500
    else:
        add_ui_log_entry("warning", "Mitmproxy is not running or process handle lost.", source="mitmproxy_control")
        mitmproxy_process = None # Ensure it's cleared
        return jsonify({"status": "warning", "message": "Mitmproxy is not running."})

@app.route('/api/mitmproxy/status', methods=['GET'])
def mitmproxy_status_api():
    # ... (Keep your existing /api/mitmproxy/status route as is) ...
    global mitmproxy_process
    is_running = False; pid = None; message = "Mitmproxy is stopped."
    if mitmproxy_process:
        if mitmproxy_process.poll() is None:
            is_running = True; pid = mitmproxy_process.pid; message = f"Mitmproxy is running (PID: {pid})."
        else: # Process has exited
            message = f"Mitmproxy process has exited (Code: {mitmproxy_process.returncode})."
            # mitmproxy_process = None # Clear the handle as it's no longer valid for a running process
    return jsonify({"status": "success", "running": is_running, "pid": pid, "message": message})

# --- Keywords API ---
# ... (Keep your existing /api/keywords routes as they are) ...
@app.route('/api/keywords', methods=['GET'])
def get_keywords_api(): return jsonify(util_get_keywords())

@app.route('/api/keywords', methods=['POST'])
def update_keywords_api():
    try:
        data = request.get_json()
        if not isinstance(data, dict): return jsonify({"status": "error", "message": "Invalid data"}), 400
        # Basic validation: ensure keys are strings, values are numbers
        valid_data = {str(k).strip().lower(): float(v) for k,v in data.items() if str(k).strip() and isinstance(v,(int,float))}
        if not valid_data: return jsonify({"status":"error", "message":"No valid keyword-score pairs provided."}),400

        if utils.update_html_keywords(valid_data): # Call the renamed util function
            utils.load_html_keywords() # Reload into memory for the main proxy script (if shared, otherwise script reloads)
            add_ui_log_entry("info", f"HTML rating keywords updated: {valid_data}", "keywords_api")
            return jsonify({"status": "success", "message": "Keywords updated successfully.", "keywords": utils.get_html_keywords()})
        add_ui_log_entry("error", "Failed to save updated HTML keywords to file.", "keywords_api")
        return jsonify({"status": "error", "message": "Failed to update keywords file."}), 500
    except ValueError as ve:
        app.logger.error(f"ValueError in /api/keywords POST: {ve}")
        add_ui_log_entry("error", f"Invalid score value provided for keyword: {ve}", "keywords_api")
        return jsonify({"status": "error", "message": f"Invalid score value: {ve}"}), 400
    except Exception as e:
        app.logger.error(f"Error in /api/keywords POST: {e}", exc_info=True)
        add_ui_log_entry("error", f"Server error updating keywords: {e}", "keywords_api")
        return jsonify({"status": "error", "message": f"Internal server error: {str(e)}"}), 500

# --- Log Event & Fetch APIs ---
# ... (Keep your existing /api/log_event and /api/logs routes as they are) ...
@app.route('/api/log_event', methods=['POST'])
def log_event_api():
    try:
        log_data = request.get_json()
        if log_data:
            add_ui_log_entry(
                log_type=log_data.get('type', 'event'),
                message=log_data.get('message', json.dumps(log_data.get('details', log_data))),
                source=log_data.get('source', 'mitmproxy_script'),
                details=log_data.get('details', {})
            )
            return jsonify({"status": "success", "message": "Log event received."}), 200
        return jsonify({"status": "error", "message": "No data provided."}), 400
    except Exception as e:
        app.logger.error(f"Error in /api/log_event: {e}", exc_info=True)
        # Do not call add_ui_log_entry here to avoid potential recursion if logging itself fails
        return jsonify({"status": "error", "message": "Failed to process log event."}), 500

@app.route('/api/logs', methods=['GET'])
def get_logs_api():
    with ui_log_lock:
        # Return a copy to avoid issues if the list is modified while iterating/serializing
        return jsonify(list(proxy_ui_log_entries))

# --- NEW: DNS Blocklist API Endpoints ---
@app.route('/api/blocklist', methods=['GET'])
def get_blocklist_api():
    global dns_blocklist_data
    with blocklist_lock:
        # For very large lists, consider pagination or returning a sample/count
        return jsonify({"status": "success", "count": len(dns_blocklist_data), "entries_sample": sorted(list(dns_blocklist_data))[:100]})

@app.route('/api/blocklist/add', methods=['POST'])
def add_to_blocklist_api():
    global dns_blocklist_data
    data = request.get_json()
    domain_to_add = data.get('domain', '').strip().lower()
    if not domain_to_add:
        return jsonify({"status": "error", "message": "Domain cannot be empty."}), 400
    if not utils.is_valid_domain(domain_to_add): # Assumes you add is_valid_domain to utils
        return jsonify({"status": "error", "message": f"Invalid domain format: {domain_to_add}"}), 400

    try:
        with blocklist_lock:
            if domain_to_add not in dns_blocklist_data:
                utils.add_domain_to_blocklist(domain_to_add, config.LOCAL_DNS_BLOCKLIST_FILE, dns_blocklist_data)
                # The main.py addon needs to be informed or reload its list.
                # Simplest is main.py reloads periodically or on next request if file changed.
                add_ui_log_entry("info", f"Domain '{domain_to_add}' added to DNS blocklist.", "blocklist_api")
                return jsonify({"status": "success", "message": f"Domain '{domain_to_add}' added."})
            else:
                return jsonify({"status": "info", "message": f"Domain '{domain_to_add}' already in blocklist."})
    except Exception as e:
        app.logger.error(f"Error adding to blocklist: {e}", exc_info=True)
        add_ui_log_entry("error", f"Failed to add domain '{domain_to_add}' to blocklist: {e}", "blocklist_api")
        return jsonify({"status": "error", "message": "Failed to add domain."}), 500

@app.route('/api/blocklist/remove', methods=['POST'])
def remove_from_blocklist_api():
    global dns_blocklist_data
    data = request.get_json()
    domain_to_remove = data.get('domain', '').strip().lower()
    if not domain_to_remove:
        return jsonify({"status": "error", "message": "Domain cannot be empty."}), 400

    try:
        with blocklist_lock:
            if domain_to_remove in dns_blocklist_data:
                utils.remove_domain_from_blocklist(domain_to_remove, config.LOCAL_DNS_BLOCKLIST_FILE, dns_blocklist_data)
                add_ui_log_entry("info", f"Domain '{domain_to_remove}' removed from DNS blocklist.", "blocklist_api")
                return jsonify({"status": "success", "message": f"Domain '{domain_to_remove}' removed."})
            else:
                return jsonify({"status": "info", "message": f"Domain '{domain_to_remove}' not found in blocklist."})
    except Exception as e:
        app.logger.error(f"Error removing from blocklist: {e}", exc_info=True)
        add_ui_log_entry("error", f"Failed to remove domain '{domain_to_remove}': {e}", "blocklist_api")
        return jsonify({"status": "error", "message": "Failed to remove domain."}), 500

@app.route('/api/blocklist/refresh', methods=['POST'])
def refresh_blocklist_api():
    """Triggers a refresh of the blocklist from the remote URL."""
    try:
        # This could take time, consider a background task for production
        initialize_blocklist() # Re-run the initialization which includes download
        return jsonify({"status": "success", "message": "Blocklist refresh initiated.", "count": len(dns_blocklist_data)})
    except Exception as e:
        app.logger.error(f"Error refreshing blocklist: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Failed to refresh blocklist: {str(e)}"}), 500


# --- Site Statistics API ---
# ... (Keep your existing /api/stats/top_sites route as is) ...
@app.route('/api/stats/top_sites', methods=['GET'])
def top_sites_stats_api():
    try:
        if not os.path.exists(TRAINING_DATA_FILE):
            return jsonify({"error": f"Training data file not found: {TRAINING_DATA_FILE}"}), 404

        df = pd.read_pickle(TRAINING_DATA_FILE)
        if df.empty:
            return jsonify({"labels": [], "datasets": [], "message": "No training data available yet."})

        if 'url' not in df.columns or 'rating' not in df.columns:
            return jsonify({"error": "Training data is missing 'url' or 'rating' columns."}), 500

        # Drop rows where rating is NaN as it cannot be aggregated
        df_cleaned = df.dropna(subset=['url', 'rating'])
        if df_cleaned.empty:
             return jsonify({"labels": [], "datasets": [], "message": "No valid rating data available."})


        # Extract domain (netloc)
        df_cleaned['domain'] = df_cleaned['url'].apply(lambda x: urlparse(x).netloc if pd.notna(x) else "unknown_domain")

        # Calculate stats per domain
        domain_stats = df_cleaned.groupby('domain')['rating'].agg(
            request_count='count',
            average_score='mean',
            best_score='max',
            lowest_score='min'
        ).reset_index()

        # Get top 5 domains by request_count
        top_5_domains_stats = domain_stats.sort_values(by='request_count', ascending=False).head(5)

        if top_5_domains_stats.empty:
            return jsonify({"labels": [], "datasets": [], "message": "Not enough data to determine top sites."})

        chart_data = {
            "labels": top_5_domains_stats['domain'].tolist(),
            "datasets": [
                {
                    "label": "Average Score (0-10)",
                    "data": top_5_domains_stats['average_score'].round(2).tolist(),
                    "backgroundColor": "rgba(54, 162, 235, 0.7)", # Blue
                    "borderColor": "rgba(54, 162, 235, 1)",
                    "borderWidth": 1
                },
                {
                    "label": "Best Score (0-10)",
                    "data": top_5_domains_stats['best_score'].round(2).tolist(),
                    "backgroundColor": "rgba(75, 192, 192, 0.7)", # Green
                    "borderColor": "rgba(75, 192, 192, 1)",
                    "borderWidth": 1
                },
                {
                    "label": "Lowest Score (0-10)",
                    "data": top_5_domains_stats['lowest_score'].round(2).tolist(),
                    "backgroundColor": "rgba(255, 99, 132, 0.7)", # Red
                    "borderColor": "rgba(255, 99, 132, 1)",
                    "borderWidth": 1
                }
            ]
        }
        return jsonify(chart_data)

    except FileNotFoundError:
        app.logger.warning(f"Training data file for stats not found: {TRAINING_DATA_FILE}")
        return jsonify({"error": "Training data file not found. Run the proxy to generate data."}), 404
    except Exception as e:
        app.logger.error(f"Error generating top sites statistics: {e}", exc_info=True)
        return jsonify({"error": f"An internal error occurred: {str(e)}"}), 500

# --- HTML Template Content (Updated) ---
# This needs to be updated to include the DNS Blocklist management section
INDEX_HTML_CONTENT_V7_BLOCKLIST = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RegressionInjection - Management UI</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: #f0f2f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 15px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #2c3e50; text-align: center; }
        h1 { margin-bottom: 30px; font-size: 2.2em; }
        h2 { margin-top: 30px; margin-bottom: 15px; border-bottom: 2px solid #007bff; padding-bottom: 8px; font-size: 1.6em;}
        .section { margin-bottom: 25px; padding: 20px; background-color: #fdfdfd; border: 1px solid #e7e7e7; border-radius: 6px; }
        label { display: block; margin-bottom: 6px; font-weight: 600; color: #555; }
        input[type="text"], input[type="number"], textarea { width: calc(100% - 22px); padding: 10px; margin-bottom: 12px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 0.95em; }
        textarea { min-height: 100px; }
        button { padding: 10px 18px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.95em; transition: background-color 0.3s ease; margin-right:8px; margin-bottom:5px;}
        button:hover { background-color: #0056b3; }
        button:disabled { background-color: #ccc; cursor: not-allowed; }
        .button-success { background-color: #28a745; } .button-success:hover { background-color: #218838; }
        .button-danger { background-color: #dc3545; } .button-danger:hover { background-color: #c82333; }
        .button-warning { background-color: #ffc107; color: #212529; } .button-warning:hover { background-color: #e0a800; }

        #keywordsList ul, #logsContainer, #blockListDisplay ul { list-style-type: none; padding: 0; }
        #keywordsList li, #blockListDisplay li { background-color: #f9f9f9; margin-bottom: 6px; padding: 10px 12px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; border-left: 4px solid #007bff; font-size:0.9em;}
        #logsContainer { max-height: 500px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; background-color: #1e1e1e; color: #d4d4d4; font-size:0.85em;}
        /* ... (other existing styles for logs, alerts, status indicators, etc. are kept the same) ... */
        .log-entry { margin-bottom: 6px; padding: 8px; border-radius: 3px; border-left: 4px solid #555; white-space: pre-wrap; font-family: 'Consolas', 'Menlo', 'Courier New', Courier, monospace; word-break: break-all; line-height:1.4;}
        .log-meta { font-size: 0.9em; color: #888; margin-bottom: 4px; border-bottom: 1px dashed #3a3a3a; padding-bottom: 3px;}
        .log-meta strong { font-weight: 600;}
        .log-request { border-left-color: #56b6c2; } .log-request .log-meta strong { color: #56b6c2; }
        .log-response_processed, .log-success { border-left-color: #67c671; } .log-response_processed .log-meta strong, .log-success .log-meta strong { color: #67c671; }
        .log-error { border-left-color: #cd3131; } .log-error .log-meta strong { color: #cd3131; } .log-error .log-message {color: #f48771;}
        .log-warning { border-left-color: #f0ad4e; } .log-warning .log-meta strong { color: #f0ad4e; }
        .log-info { border-left-color: #5bc0de; } .log-info .log-meta strong { color: #5bc0de; }
        .log-cache_hit { border-left-color: #4db5ac; } .log-cache_hit .log-meta strong { color: #4db5ac; }
        .log-cache_miss { border-left-color: #ec971f; } .log-cache_miss .log-meta strong { color: #ec971f; }
        .log-retry_add_low_rating, .log-retry_add_no_response { border-left-color: #b45fcf; } .log-retry_add_low_rating .log-meta strong, .log-retry_add_no_response .log-meta strong { color: #b45fcf; }
        .log-system, .log-system_check, .log-system_shutdown { border-left-color: #777; } .log-system .log-meta strong, .log-system_check .log-meta strong, .log-system_shutdown .log-meta strong { color: #999; }
        .log-mitmproxy_console { border-left-color: #555; color: #aaa; } .log-mitmproxy_console .log-meta strong {color: #888;}
        .log-dns_block { border-left-color: #8B0000; /* Dark Red */ } .log-dns_block .log-meta strong { color: #8B0000; }
        .log-blocklist_api, .log-blocklist_init { border-left-color: #4682B4; /* Steel Blue */ } .log-blocklist_api .log-meta strong, .log-blocklist_init .log-meta strong { color: #4682B4; }

        .log-message { margin-top: 3px; }
        .form-group { margin-bottom: 15px; }
        .instructions { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-top:12px; border: 1px solid #dee2e6;}
        .instructions h4 { margin-top: 0; color: #0056b3; font-size: 1.1em;}
        .instructions ul, .instructions ol { padding-left: 20px; margin-top:5px; margin-bottom:10px; font-size:0.9em;}
        .instructions code { background-color: #e9ecef; padding: 2px 5px; border-radius: 3px; font-family: 'Courier New', Courier, monospace; border: 1px solid #ced4da; color: #c7254e;}
        .alert-warning { padding: 12px; background-color: #fff3cd; border: 1px solid #ffeeba; color: #856404; border-radius: 4px; margin-bottom: 15px; font-size:0.9em;}
        .status-indicator { padding: 6px 12px; border-radius: 4px; color: white; font-weight: bold; display:inline-block; font-size:0.9em;}
        .status-running { background-color: #28a745; }
        .status-stopped { background-color: #dc3545; }
        .status-unknown { background-color: #ffc107; color: #333;}
        .proxy-controls { margin-bottom:10px;}
        .proxy-controls button {margin-top:5px;}
        details { margin-top: 10px; border: 1px solid #ddd; border-radius: 4px; }
        summary { padding: 10px; font-weight: bold; cursor: pointer; background-color: #f7f7f7; border-radius: 4px 4px 0 0;}
        details[open] summary { border-bottom: 1px solid #ddd; }
        details > div { padding: 15px; background-color: #fff; border-top: 1px solid #eee;}
        .chart-container { width: 90%; max-width: 800px; margin: 20px auto; padding:10px; border: 1px solid #ddd; border-radius: 5px; background-color: #fff;}
        #blockListDisplay { max-height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; margin-top: 10px; }
        #blockListDisplay li span { flex-grow: 1; }
        #blockListDisplay li button { font-size: 0.8em; padding: 3px 6px; margin-left: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RegressionInjection - Management UI</h1>

        <div class="section" id="proxyControlSection">
            <h2>Mitmproxy Control</h2>
            <p>Status: <span id="mitmproxyStatusIndicator" class="status-indicator status-{{ mitmproxy_status.lower() }}">{{ mitmproxy_status }}</span></p>
            <div class="proxy-controls">
                <button id="startProxyButton" onclick="startProxy()">Start Proxy</button>
                <button id="stopProxyButton" onclick="stopProxy()" class="button-danger">Stop Proxy</button>
                <button id="refreshStatusButton" onclick="checkProxyStatus()">Refresh Status</button>
            </div>
            <p><small>Mitmproxy console output will appear in the 'Live Proxy Log Stream' below.</small></p>
        </div>

        <div class="section" id="siteStatsSection">
             <h2>Top Site Statistics</h2>
             <div class="chart-container"> <canvas id="topSitesChart"></canvas> </div>
             <div style="text-align:center; margin-top:10px;"> <button onclick="fetchTopSitesStats()">Refresh Stats</button> </div>
             <p id="statsMessage" style="text-align:center; margin-top:10px;"></p>
        </div>

        <div class="section" id="certificateSection">
            <h2>Step 1: Proxy Setup & CA Certificate</h2>
            <div id="caCertInfo">
                <p>To intercept HTTPS traffic, your browser/OS must trust the mitmproxy CA certificate.</p>
                {% if ca_cert_exists %}
                    <a href="/download-ca-certificate" download="{{ ca_cert_filename }}">
                        <button class="button-success">Download {{ ca_cert_filename }}</button>
                    </a>
                    <p><small>Certificate found at: <code>{{ MITMPROXY_CERT_DIR }}/{{ ca_cert_filename }}</code> on the server.</small></p>
                {% else %}
                    <div class="alert-warning">
                        <strong>CA Certificate Not Found!</strong>
                         <ol style="margin-top:10px; margin-bottom:0; padding-left:20px;">
                            <li>The certificate file (<code>{{ ca_cert_filename }}</code>) was not found in the expected directory: <code>{{ MITMPROXY_CERT_DIR }}</code>.</li>
                            <li><strong>Action:</strong> Click the "Start Proxy" button in the section above. Mitmproxy should automatically generate this certificate file when it starts for the first time with this configuration directory.</li>
                            <li>After starting the proxy, wait about 5-10 seconds for initialization.</li>
                            <li>Then, <button onclick="window.location.reload()" style="padding:3px 6px; font-size:0.8em;">Refresh this Page</button>. The download link should appear if the certificate was created.</li>
                            <li>If the download link still doesn't appear, check the "Live Proxy Log Stream" below for any errors from mitmproxy during startup (e.g., permission issues writing to the certificate directory).</li>
                        </ol>
                    </div>
                {% endif %}
            </div>
            <div class="instructions">
                <h4>Step 2: Configure Your System/Browser to Use the Proxy:</h4>
                <p>Once mitmproxy is running (see status above), configure your browser or entire system to use the following HTTP/HTTPS proxy settings:</p>
                <ul>
                    <li><strong>Proxy Host/Server:</strong> <code>{{ mitmproxy_host }}</code> (or <code>localhost</code> if running on the same machine)</li>
                    <li><strong>Proxy Port:</strong> <code>{{ mitmproxy_port }}</code></li>
                </ul>
                <h4>Step 3: Install the Downloaded Certificate (Crucial Manual Step):</h4>
                <p>After downloading <code>{{ ca_cert_filename }}</code>, you MUST manually install it into your browser's or operating system's list of trusted certificate authorities.</p>
                <details><summary><strong>Windows</strong> - Detailed Instructions</summary><div><ol><li><strong>Locate File:</strong> Find <code>{{ ca_cert_filename }}</code>.</li><li><strong>Start Import:</strong> Double-click the <code>.pem</code> file.</li><li><strong>Install:</strong> Click "Install Certificate...".</li><li><strong>Store Location:</strong> Choose "Current User". Click Next.</li><li><strong>Certificate Store:</strong> Select "Place all certificates in the following store". Click "Browse...". Choose "Trusted Root Certification Authorities". Click OK, then Next.</li><li><strong>Confirm:</strong> Click Next, then "Finish".</li><li><strong>Security Warning:</strong> Click "Yes" if prompted.</li><li><strong>Restart Browser.</strong></li></ol></div></details>
                <details><summary><strong>macOS</strong> - Detailed Instructions</summary><div><ol><li><strong>Locate File.</strong></li><li><strong>Keychain Access:</strong> Double-click <code>.pem</code> file or drag into Keychain Access ("login" keychain).</li><li><strong>Find Certificate:</strong> Find "mitmproxy".</li><li><strong>Set Trust:</strong> Double-click it, expand "Trust", set "When using this certificate:" to "Always Trust".</li><li>Enter password if prompted.</li><li><strong>Restart Browser.</strong></li></ol></div></details>
                <details><summary><strong>Linux (Debian/Ubuntu based)</strong> - Detailed Instructions</summary><div><ol><li><strong>Locate File.</strong></li><li><strong>Prepare and Copy (Terminal):</strong><br><code>mv {{ ca_cert_filename }} mitmproxy-ca.crt</code><br><code>sudo cp mitmproxy-ca.crt /usr/local/share/ca-certificates/mitmproxy-ca.crt</code></li><li><strong>Update System CA Store:</strong><br><code>sudo update-ca-certificates</code></li><li><strong>Restart Browser.</strong></li></ol></div></details>
                <details><summary><strong>Firefox (All Platforms)</strong> - Detailed Instructions</summary><div><ol><li><strong>Settings:</strong> Menu > Settings > Privacy & Security.</li><li><strong>Certificates:</strong> Scroll to "Certificates", click "View Certificates...".</li><li><strong>Authorities Tab:</strong> Select "Authorities".</li><li><strong>Import:</strong> Click "Import...", select <code>{{ ca_cert_filename }}</code>.</li><li><strong>Trust Settings:</strong> Check "Trust this CA to identify websites.". Click "OK".</li><li><strong>Restart Firefox.</strong></li></ol></div></details>
                 <p style="margin-top:15px;"><em><strong style="color:red;">Security Note:</strong> You are installing a Root CA. Only do this for CAs you trust.</em></p>
            </div>
        </div>

        <div class="section">
            <h2>HTML Content Rating Keywords (Scores {{RATING_SCALE_MIN}}-{{RATING_SCALE_MAX}})</h2>
            <div id="keywordsDisplay"><p>Loading keywords...</p></div>
            <div class="form-group">
                <h3>Add/Update Keyword</h3>
                <label for="keywordInput">Keyword (e.g., <code>captcha</code>, <code>login success</code> - case-insensitive):</label>
                <input type="text" id="keywordInput" placeholder="Enter keyword">
                <label for="scoreInput">Score ({{RATING_SCALE_MIN}}-{{RATING_SCALE_MAX}}, e.g., <code>0.5</code> for captcha, <code>9.0</code> for login success):</label>
                <input type="number" id="scoreInput" placeholder="Enter score ({{RATING_SCALE_MIN}}-{{RATING_SCALE_MAX}})" step="0.1" min="{{RATING_SCALE_MIN}}" max="{{RATING_SCALE_MAX}}">
            </div>
            <div class="keyword-actions"> <button onclick="addOrUpdateKeyword()">Save Keyword</button> </div>
            <div class="form-group" style="margin-top: 20px;">
                <h3>Neutralize Keyword (Set Score to 0)</h3>
                <label for="neutralizeKeywordInput">Enter keyword to set its score to 0:</label>
                <input type="text" id="neutralizeKeywordInput" placeholder="Keyword to neutralize">
                <button class="button-danger" onclick="neutralizeKeyword()">Set Score to 0</button>
            </div>
        </div>

        <div class="section" id="dnsBlocklistSection">
            <h2>DNS Blocklist Management</h2>
            <p>Currently <strong id="dnsBlocklistCount">{{ dns_blocklist_count }}</strong> domains in the blocklist.
               The list is primarily managed by an external source and updated on server start.
               You can add or remove specific domains locally.
            </p>
            <button onclick="refreshBlocklist()" class="button-warning">Refresh Blocklist from Source</button>
            <div class="form-group" style="margin-top: 15px;">
                <label for="domainInput">Domain (e.g., <code>example.com</code>):</label>
                <input type="text" id="domainInput" placeholder="Enter domain to add/remove">
            </div>
            <button onclick="addBlocklistDomain()">Add Domain</button>
            <button onclick="removeBlocklistDomain()" class="button-danger">Remove Domain</button>

            <h3>Current Blocklist Sample (First 100 entries - Local View)</h3>
            <div id="blockListDisplay"><p>Loading blocklist sample...</p></div>
             <p><small>Note: Changes made here modify a local version of the blocklist. The main proxy uses this local version. Refreshing from source will overwrite the base list but preserve your local additions/removals if implemented in utils.py correctly (e.g., separate user list).</small></p>
        </div>

        <div class="section">
            <h2>Live Proxy Log Stream (Newest First - Max {{ MAX_LOG_ENTRIES_UI }} entries)</h2>
            <div id="logsContainer"><p style="color:#888;">Waiting for logs...</p></div>
        </div>
    </div>

    <script>
        // --- Global JS Variables (same) ---
        const API_BASE_URL = '';
        const MAX_LOG_ENTRIES_JS = parseInt("{{ MAX_LOG_ENTRIES_UI }}", 10);
        let currentMitmproxyStatus = "{{ mitmproxy_status }}";
        let topSitesChartInstance = null;

        // --- Mitmproxy Control JS (same) ---
        function updateProxyStatusIndicator(statusText, pid) { /* ... same as your original ... */
            const indicator = document.getElementById('mitmproxyStatusIndicator');
            const startButton = document.getElementById('startProxyButton');
            const stopButton = document.getElementById('stopProxyButton');
            indicator.textContent = statusText + (pid ? ` (PID: ${pid})` : '');
            indicator.className = 'status-indicator';
            if (statusText.toLowerCase().includes('running')) {
                indicator.classList.add('status-running'); startButton.disabled = true; stopButton.disabled = false;
            } else if (statusText.toLowerCase().includes('stopped') || statusText.toLowerCase().includes('exited')) {
                indicator.classList.add('status-stopped'); startButton.disabled = false; stopButton.disabled = true;
            } else {
                indicator.classList.add('status-unknown'); startButton.disabled = true; stopButton.disabled = true; // Or some other default
            }
        }
        async function checkProxyStatus() { /* ... same as your original ... */
            try {
                const response = await fetch(`${API_BASE_URL}/api/mitmproxy/status`);
                const data = await response.json();
                let newStatus = "Error Checking"; let newPid = null;
                if (response.ok && data.status === 'success') {
                    newStatus = data.running ? 'Running' : (data.message.includes("exited") ? "Exited" : "Stopped");
                    newPid = data.pid;
                } else if (response.ok) { newStatus = data.message || "Unknown Status from API"; }
                currentMitmproxyStatus = newStatus;
                updateProxyStatusIndicator(currentMitmproxyStatus, newPid);
                const caCertSection = document.getElementById('caCertInfo');
                const downloadButtonExists = caCertSection.querySelector('a[href="/download-ca-certificate"] button');
                 if (data.running && !downloadButtonExists && !document.querySelector('#caCertInfo .alert-warning button')) { // Avoid reload if warning already shows reload button
                     // Consider if auto-refresh is desired or if user should manually refresh
                     // window.location.reload();
                     console.log("Proxy running. If CA cert was missing, refresh page for download link.");
                }
            } catch (error) { console.error('Error checking mitmproxy status:', error); updateProxyStatusIndicator('Network Error Checking Status'); }
        }
        async function startProxy() { /* ... same as your original ... */
            updateProxyStatusIndicator('Starting...', null);
            try {
                const response = await fetch(`${API_BASE_URL}/api/mitmproxy/start`, { method: 'POST' });
                const result = await response.json();
                addLogToUI({type: response.ok && result.status === 'success' ? 'info' : 'error', source: 'ui_control', message: `Start Proxy: ${result.message}`});
            } catch (error) { console.error('Client error starting proxy:', error); addLogToUI({type: 'error', source: 'ui_control', message: 'Client-side error sending start command.'});}
            setTimeout(checkProxyStatus, 2500); // Give mitmproxy time to start/fail
        }
        async function stopProxy() { /* ... same as your original ... */
            updateProxyStatusIndicator('Stopping...', null);
            try {
                const response = await fetch(`${API_BASE_URL}/api/mitmproxy/stop`, { method: 'POST' });
                const result = await response.json();
                addLogToUI({type: response.ok && result.status === 'success' ? 'info' : 'error', source: 'ui_control', message: `Stop Proxy: ${result.message}`});
            } catch (error) { console.error('Client error stopping proxy:', error); addLogToUI({type: 'error', source: 'ui_control', message: 'Client-side error sending stop command.'});}
            setTimeout(checkProxyStatus, 2000);
        }

        // --- Keywords JS (same) ---
        async function fetchKeywords() { /* ... same as your original ... */
            try {
                const response = await fetch(`${API_BASE_URL}/api/keywords`);
                if (!response.ok) throw new Error(`Keywords API error! status: ${response.status}`);
                const keywords = await response.json();
                const displayDiv = document.getElementById('keywordsDisplay');
                let html = '<h4>Current Keywords & Scores ({{RATING_SCALE_MIN}}-{{RATING_SCALE_MAX}}):</h4>';
                if (Object.keys(keywords).length === 0) { html += '<p>No keywords defined yet.</p>'; }
                else { html += '<ul style="padding-left: 20px;">'; for (const [key, value] of Object.entries(keywords)) { html += `<li><span><strong>${key}:</strong> ${value.toFixed(1)}</span></li>`; } html += '</ul>'; }
                displayDiv.innerHTML = html;
            } catch (error) { console.error('Error fetching keywords:', error); document.getElementById('keywordsDisplay').innerHTML = '<p style="color:red;">Error loading keywords.</p>';}
        }
        async function addOrUpdateKeyword() { /* ... same as your original ... */
            const keyword = document.getElementById('keywordInput').value.trim().toLowerCase();
            const scoreInput = document.getElementById('scoreInput').value;
            if (!keyword) { addLogToUI({type:'warning', source:'ui_keywords', message:'Keyword cannot be empty.'}); return; }
            if (scoreInput === '') { addLogToUI({type:'warning', source:'ui_keywords', message:'Score cannot be empty.'}); return; }
            const score = parseFloat(scoreInput);
            if (isNaN(score)) { addLogToUI({type:'warning', source:'ui_keywords', message:'Score must be a valid number.'}); return; }
            const minScale = parseFloat("{{RATING_SCALE_MIN}}"); const maxScale = parseFloat("{{RATING_SCALE_MAX}}");
            if (score < minScale || score > maxScale) {
                 addLogToUI({type:'warning', source:'ui_keywords', message:`Score must be between ${minScale} and ${maxScale}.`}); return;
            }
            try {
                const payload = { [keyword]: score };
                const response = await fetch(`${API_BASE_URL}/api/keywords`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)});
                const result = await response.json();
                addLogToUI({type: response.ok && result.status === 'success' ? 'info' : 'error', source:'ui_keywords', message: `Keyword update for '${keyword}': ${result.message}`});
                if (result.status === 'success') { fetchKeywords(); document.getElementById('keywordInput').value = ''; document.getElementById('scoreInput').value = '';}
            } catch (e) { console.error(e); addLogToUI({type:'error', source:'ui_keywords', message:`Client error updating keyword: ${e.message}`});}
        }
        async function neutralizeKeyword() { /* ... same as your original ... */
             const keywordToNeutralize = document.getElementById('neutralizeKeywordInput').value.trim().toLowerCase();
            if (!keywordToNeutralize) { addLogToUI({type:'warning', source:'ui_keywords', message:'Keyword to neutralize cannot be empty.'}); return; }
            try {
                const payload = { [keywordToNeutralize]: 0.0 }; // Neutral score
                const response = await fetch(`${API_BASE_URL}/api/keywords`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)});
                const result = await response.json();
                addLogToUI({type: response.ok && result.status === 'success' ? 'info' : 'error', source:'ui_keywords', message: `Keyword '${keywordToNeutralize}' neutralized: ${result.message}`});
                if (result.status === 'success') { fetchKeywords(); document.getElementById('neutralizeKeywordInput').value = '';}
            } catch (e) { console.error(e); addLogToUI({type:'error', source:'ui_keywords', message:`Client error neutralizing keyword: ${e.message}`});}
        }


        // --- Logs JS (same) ---
        const logsContainer = document.getElementById('logsContainer');
        /* ... same as your original ... */
        let isAutoScrollLogs = false; // Initialize to false
        if(logsContainer) {
            logsContainer.addEventListener('scroll', () => {
                isAutoScrollLogs = logsContainer.scrollHeight - logsContainer.scrollTop <= logsContainer.clientHeight + 50; // Check if near bottom
            });
        }
        function addLogToUI(logEntryData) {
            const logsContainer = document.getElementById('logsContainer'); if (!logsContainer) return;
            const firstChild = logsContainer.firstChild;
            if (firstChild && firstChild.nodeType === Node.ELEMENT_NODE && firstChild.tagName === 'P' && (firstChild.textContent.includes("Waiting for logs...") || firstChild.textContent.includes("No logs yet."))) {
                logsContainer.innerHTML = ''; // Clear placeholder
            }
            const entryElement = formatLogEntry(logEntryData);
            const shouldScroll = isAutoScrollLogs || logsContainer.children.length < 10; // Auto-scroll if few logs or already at bottom

            logsContainer.insertBefore(entryElement, logsContainer.firstChild); // Add to top (newest first)

            while (logsContainer.children.length > MAX_LOG_ENTRIES_JS) {
                logsContainer.removeChild(logsContainer.lastChild);
            }
            // if (shouldScroll) { logsContainer.scrollTop = 0; } // Scroll to top if adding to top
        }
         function formatLogEntry(log) {
            const entryDiv = document.createElement('div');
            const typeClass = (log.type || 'unknown').toString().replace(/[^a-z0-9_]/gi, '_').toLowerCase();
            entryDiv.classList.add('log-entry', `log-${typeClass}`);

            let originalTimestamp = log.timestamp ? new Date(log.timestamp * 1000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 2 }) : "N/A";
            let source = log.source || "unknown";
            let detailsHTML = '';

            if (log.details) {
                if (log.details.url) detailsHTML += `<div><small>URL: ${escapeHtml(log.details.url)}</small></div>`;
                if (log.details.method) detailsHTML += `<small>Method: ${escapeHtml(log.details.method)} | </small>`;
                if (log.details.status) detailsHTML += `<small>Status: ${escapeHtml(String(log.details.status))} | </small>`;
                if (log.details.rating !== undefined) detailsHTML += `<small>Rating: ${typeof log.details.rating === 'number' ? log.details.rating.toFixed(1) : escapeHtml(String(log.details.rating))} | </small>`;
                if (log.details.duration_ms !== undefined) detailsHTML += `<small>Time: ${escapeHtml(String(log.details.duration_ms))}ms | </small>`;
                if (log.details.error) detailsHTML += `<div style="color:#ffc4c4;"><small>Error Detail: ${escapeHtml(log.details.error)}</small></div>`;
            }

            let content = `<div class="log-meta"><span>${escapeHtml(originalTimestamp)}</span> | Type: <strong>${escapeHtml(log.type || 'N/A')}</strong> | Src: ${escapeHtml(source)}${log.details && log.details.flow_id ? ` | Flow: ${escapeHtml(log.details.flow_id)}` : ''}</div>`;

            const tempDivMsg = document.createElement('div'); tempDivMsg.textContent = log.message || ""; // Safely set text content first
            if (tempDivMsg.textContent) { // Check if there is a message after setting textContent
                 let msgClass = '';
                 if (log.type === 'error' || (log.source && log.source.includes('error'))) msgClass = 'log-error-message';
                 else if (log.type === 'warning' || (log.source && source.includes('warning'))) msgClass = 'log-warning-message';
                 content += `<div class="log-message ${msgClass}">${tempDivMsg.innerHTML}</div>`; // Use innerHTML of the tempDiv to get escaped version
            }
            if(detailsHTML) content += `<div class="log-entry-details">${detailsHTML}</div>`; // detailsHTML is already escaped
            entryDiv.innerHTML = content;
            return entryDiv;
        }
        async function fetchLogs() { /* ... same as your original ... */
            if(!logsContainer) return;
            try {
                const response = await fetch(`${API_BASE_URL}/api/logs`);
                if (!response.ok) { console.error(`HTTP error fetching logs! status: ${response.status}`); return; }
                const logs = await response.json();

                const firstChild = logsContainer.firstChild;
                 if (firstChild && firstChild.nodeType === Node.ELEMENT_NODE && firstChild.tagName === 'P' && (firstChild.textContent.includes("Waiting for logs...") || firstChild.textContent.includes("No logs yet."))) {
                    logsContainer.innerHTML = ''; // Clear placeholder only if it's the only thing there or first.
                }

                logsContainer.innerHTML = ''; // Clear all existing logs to re-render
                if (logs && logs.length > 0) {
                    logs.slice(0, MAX_LOG_ENTRIES_JS).forEach(log => {
                        logsContainer.appendChild(formatLogEntry(log)); // Append, formatLogEntry adds to top internally
                    });
                } else if (logsContainer.children.length === 0) { // Check if still empty after potential clear
                    logsContainer.innerHTML = '<p style="color:#888;">No logs yet.</p>';
                }
            } catch (error) { console.error('Error fetching logs:', error); }
        }


        // --- Charting JS (same) ---
        async function fetchTopSitesStats() { /* ... same as your original ... */
            const statsMessageEl = document.getElementById('statsMessage');
            statsMessageEl.textContent = 'Loading stats...';
            try {
                const response = await fetch(`${API_BASE_URL}/api/stats/top_sites`);
                if (!response.ok) {
                    const errData = await response.json().catch(() => ({error: "Failed to parse error from stats API"}));
                    throw new Error(`Stats API error ${response.status}: ${errData.error || "Unknown error"}`);
                }
                const data = await response.json();

                if (data.error) {
                    statsMessageEl.textContent = `Error loading stats: ${data.error}`;
                    addLogToUI({type: 'error', source: 'ui_stats', message: `Error from /api/stats/top_sites: ${data.error}`});
                    return;
                }
                if (!data.labels || data.labels.length === 0) {
                    statsMessageEl.textContent = data.message || 'No site data available for charting yet.';
                    if (topSitesChartInstance) { topSitesChartInstance.destroy(); topSitesChartInstance = null; }
                    return;
                }
                statsMessageEl.textContent = '';

                const ctx = document.getElementById('topSitesChart').getContext('2d');
                if (topSitesChartInstance) { topSitesChartInstance.destroy(); }
                topSitesChartInstance = new Chart(ctx, {
                    type: 'bar',
                    data: { labels: data.labels, datasets: data.datasets.map(ds => ({ ...ds, barPercentage: 0.7, categoryPercentage: 0.8 })) },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        scales: { y: { beginAtZero: true, suggestedMax: parseFloat("{{RATING_SCALE_MAX}}"), title: { display: true, text: 'Score (0-10)' } },
                                  x: { title: { display: true, text: 'Top 5 Requested Domains' } } },
                        plugins: { legend: { position: 'top' }, title: { display: true, text: 'Site Request Score Analysis (Avg, Best, Lowest)' } }
                    }
                });
                addLogToUI({type: 'info', source: 'ui_stats', message: 'Top sites chart updated.'});
            } catch (error) {
                console.error('Error fetching or rendering top sites stats:', error);
                statsMessageEl.textContent = `Error: ${error.message}`;
                addLogToUI({type: 'error', source: 'ui_stats', message: `Client error fetching/rendering stats: ${error.message}`});
            }
        }

        // --- NEW: DNS Blocklist JS ---
        async function fetchBlocklistSample() {
            const displayDiv = document.getElementById('blockListDisplay');
            displayDiv.innerHTML = '<p>Loading blocklist sample...</p>';
            try {
                const response = await fetch(`${API_BASE_URL}/api/blocklist`);
                const data = await response.json();
                if (response.ok && data.status === 'success') {
                    document.getElementById('dnsBlocklistCount').textContent = data.count;
                    if (data.entries_sample && data.entries_sample.length > 0) {
                        let html = '<ul>';
                        data.entries_sample.forEach(domain => {
                            html += `<li><span>${escapeHtml(domain)}</span> <button onclick="removeBlocklistDomain('${escapeHtml(domain)}')">Remove</button></li>`;
                        });
                        html += '</ul>';
                        displayDiv.innerHTML = html;
                    } else {
                        displayDiv.innerHTML = '<p>Blocklist is empty or no sample available.</p>';
                    }
                } else {
                    displayDiv.innerHTML = `<p style="color:red;">Error: ${data.message || 'Could not load blocklist sample.'}</p>`;
                }
            } catch (error) {
                console.error('Error fetching blocklist sample:', error);
                displayDiv.innerHTML = '<p style="color:red;">Client error fetching blocklist sample.</p>';
            }
        }

        async function addBlocklistDomain(domainFromClick = null) {
            const domain = domainFromClick || document.getElementById('domainInput').value.trim().toLowerCase();
            if (!domain) {
                addLogToUI({type:'warning', source:'ui_blocklist', message:'Domain cannot be empty.'});
                return;
            }
            try {
                const response = await fetch(`${API_BASE_URL}/api/blocklist/add`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: domain })
                });
                const result = await response.json();
                addLogToUI({type: response.ok && result.status === 'success' ? 'info' : 'error', source:'ui_blocklist', message: `Add '${domain}': ${result.message}`});
                if (response.ok && result.status === 'success') {
                    document.getElementById('domainInput').value = '';
                    fetchBlocklistSample(); // Refresh display
                }
            } catch (e) {
                console.error(e);
                addLogToUI({type:'error', source:'ui_blocklist', message:`Client error adding domain: ${e.message}`});
            }
        }

        async function removeBlocklistDomain(domainFromClick = null) {
            const domain = domainFromClick || document.getElementById('domainInput').value.trim().toLowerCase();
            if (!domain) {
                addLogToUI({type:'warning', source:'ui_blocklist', message:'Domain to remove cannot be empty.'});
                return;
            }
            try {
                const response = await fetch(`${API_BASE_URL}/api/blocklist/remove`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: domain })
                });
                const result = await response.json();
                addLogToUI({type: response.ok && result.status === 'success' ? 'info' : 'error', source:'ui_blocklist', message: `Remove '${domain}': ${result.message}`});
                if (response.ok && result.status === 'success') {
                    document.getElementById('domainInput').value = '';
                    fetchBlocklistSample(); // Refresh display
                }
            } catch (e) {
                console.error(e);
                addLogToUI({type:'error', source:'ui_blocklist', message:`Client error removing domain: ${e.message}`});
            }
        }
        async function refreshBlocklist() {
            addLogToUI({type: 'info', source: 'ui_blocklist', message: 'Attempting to refresh blocklist from source...'});
            try {
                const response = await fetch(`${API_BASE_URL}/api/blocklist/refresh`, { method: 'POST'});
                const result = await response.json();
                addLogToUI({type: response.ok && result.status === 'success' ? 'info' : 'error', source:'ui_blocklist', message: `Blocklist refresh: ${result.message}`});
                if (response.ok && result.status === 'success') {
                    document.getElementById('dnsBlocklistCount').textContent = result.count;
                    fetchBlocklistSample();
                }
            } catch (e) {
                console.error(e);
                addLogToUI({type:'error', source:'ui_blocklist', message:`Client error refreshing blocklist: ${e.message}`});
            }
        }

        function escapeHtml(unsafe) {
            if (typeof unsafe !== 'string') {
                if (unsafe === null || typeof unsafe === 'undefined') return '';
                try { unsafe = String(unsafe); } catch (e) { return ''; }
            }
            return unsafe
                 .replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
        }


        document.addEventListener('DOMContentLoaded', () => {
            updateProxyStatusIndicator(currentMitmproxyStatus, null);
            fetchKeywords();
            fetchLogs();
            fetchTopSitesStats();
            fetchBlocklistSample(); // Fetch blocklist on load

            setInterval(fetchLogs, 2000);
            setInterval(checkProxyStatus, 3000);
        });
    </script>
</body>
</html>
"""

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
if not os.path.exists(TEMPLATES_DIR):
    os.makedirs(TEMPLATES_DIR)

# Write the updated HTML content to index.html
with open(os.path.join(TEMPLATES_DIR, 'index.html'), 'w', encoding='utf-8') as f:
    f.write(INDEX_HTML_CONTENT_V7_BLOCKLIST)


if __name__ == '__main__':
    app.logger.info(f"Starting management server on http://{MANAGEMENT_SERVER_HOST}:{MANAGEMENT_SERVER_PORT}")
    app.logger.info(f"Mitmproxy CA certificate expected at: {CA_CERT_PATH}")
    app.logger.info(f"HTML Keywords JSON: {HTML_RATING_KEYWORDS_FILE}")
    app.logger.info(f"Training data for stats expected at: {TRAINING_DATA_FILE}")
    app.logger.info(f"DNS Blocklist URL: {config.DNS_BLOCKLIST_URL}")
    app.logger.info(f"Local DNS Blocklist File: {config.LOCAL_DNS_BLOCKLIST_FILE}")

    utils.load_html_keywords() # Load HTML keywords
    initialize_blocklist()   # Initialize DNS blocklist (download and load)

    app.run(host=MANAGEMENT_SERVER_HOST, port=MANAGEMENT_SERVER_PORT, debug=False, use_reloader=False)