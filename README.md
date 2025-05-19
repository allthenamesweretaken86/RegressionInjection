# RegressionInjection: Intelligent HTTP Proxy

RegressionInjection is an advanced HTTP/HTTPS proxy system built with Python and `mitmproxy`. It leverages machine learning to optimize web requests, improve success rates, and ensure high-quality page loads. The system features intelligent caching, a DNS blocklist, automatic retry mechanisms for failed or low-quality requests, and a web-based management UI.

## Core Features

1.  **Intelligent Proxying with `mitmproxy`**:
    * Intercepts HTTP and HTTPS traffic.
    * Acts as the backbone for request/response manipulation and data collection.

2.  **DNS Blocklist Integration**:
    * **Automatic Updates**: On startup, the system downloads and loads a DNS blocklist from a configurable URL (e.g., Hagezi's Pro blocklist).
    * **Request Filtering**: URLs whose domains match entries in the blocklist are dropped early in the request lifecycle. This prevents them from being processed for caching, model training, or other resource-intensive operations.
    * **UI Management**: The web management UI allows:
        * Viewing the current blocklist entry count.
        * Manually adding or removing domains from a local version of the blocklist.
        * Triggering a refresh of the blocklist from its remote source.

3.  **Machine Learning for Request Optimization**:
    * Uses a `DecisionTreeRegressor` model (from scikit-learn) to predict the "quality" or "success likelihood" of a web request based on its parameters and the resulting response.
    * **Adaptive Feature Learning**: The system captures a comprehensive set of request parameters, including:
        * Standard HTTP headers (User-Agent, Accept, Accept-Language, Host, Origin, Referer, etc.).
        * Security and Fetch Metadata headers (`Sec-Fetch-*`).
        * Request content length.
        * Client IP address, TLS fingerprint, HTTP version.
        * Dynamically identifies and incorporates common custom `X-*` headers from traffic into its feature set.
    * Continuously trains the model with new data from live (non-blocked) traffic.

4.  **Advanced Rating System (0-10 Scale)**:
    * Responses are rated on a 0-10 scale, where 0 indicates a complete failure or very poor quality, and 10 represents an ideal, successful page load.
    * The rating is determined by:
        * **HTTP Status Code**: (e.g., 2xx are high, 4xx/5xx are low).
        * **HTML Content Analysis**:
            * **Keywords**: User-configurable keywords (via UI or JSON file) found in HTML content directly influence the score (e.g., "captcha", "login required" drastically lower the score; "success" might increase it).
            * **HTML Length**: A scoring component rewards pages with more substantial HTML content, assuming it often correlates with a more complete page.
        * **Dominant HTML Keywords**: Certain keywords can heavily sway or override the rating if detected.

5.  **Smart Caching**:
    * Caches successful and high-quality responses based on URL and other request characteristics for non-blocked requests.
    * Reduces latency and server load for frequently accessed resources.
    * Manages cache expiry and maximum size.

6.  **Automatic Retry Management**:
    * If a request results in a low rating (below a configurable threshold, e.g., < 4.0/10), the `RetryManager` queues it for a retry.
    * **Optimized Retries**: For retry attempts, the manager:
        * Consults the machine learning model to fetch patterns of headers and parameters that historically led to high-quality responses for similar requests.
        * Modifies the request (e.g., changes User-Agent, Accept headers) based on these learned patterns or fallback strategies.
        * Uses exponential backoff with jitter for scheduling retries.

7.  **Performance Monitoring**:
    * Tracks key metrics: request/response counts, processing times, cache hit/miss rates, error rates, retry statistics, and DNS blocked request counts.
    * Saves metrics periodically.

8.  **Web-Based Management UI (Flask)**:
    * **Proxy Control**: Start and stop the `mitmproxy` instance directly from the UI.
    * **CA Certificate Management**:
        * Guides the user through the HTTPS interception setup.
        * Provides a download link for the `mitmproxy` CA certificate once generated.
        * Displays clear, step-by-step instructions for installing the CA certificate in various browsers and operating systems.
    * **HTML Keyword Configuration**: Add, update, or neutralize keywords and their associated scores (0-10) used in the HTML content rating system.
    * **DNS Blocklist Management**: View blocklist status, add/remove custom domains, and trigger a refresh from the source URL.
    * **Site Statistics**: View charts for top requested domains, including average, best, and lowest scores.
    * **Live Logging**: Displays a stream of logs, including:
        * Structured logs from the proxy's internal operations (e.g., request processing, DNS blocks, cache events, errors).
        * Console output (stdout/stderr) from the underlying `mitmproxy` process.

## Goal

The primary goal of RegressionInjection is to maximize the likelihood of fetching the **expected and high-quality HTML content** for the user, while respecting privacy and safety through blocklists. It achieves this by:
* Filtering out unwanted requests using a DNS blocklist.
* Learning what constitutes a "good" vs. "bad" page load through its comprehensive rating system for allowed traffic.
* Adapting request parameters based on learned successful patterns.
* Automatically retrying requests that yield low-quality data, aiming for a better outcome on subsequent attempts.

## How It Works: Data Flow & Learning Loop

1.  **Management Server Startup**: `management_server.py` starts.
    * Initializes and loads/downloads the DNS blocklist (`dns_blocklist.txt`) via `utils.py`.
2.  **Request Interception**: `main.py` (mitmproxy addon) intercepts a request.
3.  **DNS Blocklist Check**: The request URL's domain is checked against the loaded DNS blocklist by `utils.is_url_blocked()`.
    * If blocked, a 403 response is returned, and processing stops for this request.
4.  **Feature Extraction (if not blocked)**: Request parameters (headers, URL, method, etc.) are extracted into a dictionary stored in `flow.metadata`.
5.  **Cache Check**: `cache.py` checks if a valid cached response exists. If yes, it's served.
6.  **Request to Server (if no cache hit/not blocked)**: The request proceeds to the target server.
7.  **Response Processing**:
    * The response is received.
    * `utils.py` rates the response (0-10) based on status code, HTML keywords, and HTML length.
    * Response features (status, HTML length, rating, etc.) are added to the features dictionary in `flow.metadata`.
8.  **Data Storage & Model Training**:
    * The complete features dictionary is used to instantiate a `RequestFeatures` object.
    * This object is passed to `request_features.py` which stores it in a training dataset (`training_data_v2.pkl`).
    * Periodically, `model.py` uses this dataset to (re)train the `DecisionTreeRegressor`. The model learns to predict the `rating` based on the input features.
    * The model, scaler, and identified common custom header keys are saved.
9.  **Retry Logic**:
    * If the response `rating` is below `RETRY_THRESHOLD_RATING`, `main.py` informs `retry_manager.py`.
    * `retry_manager.py` queues the request. When it's time to retry:
        * It queries `model.py` for high-quality request patterns.
        * It constructs a new, modified request using these optimized parameters.
        * The modified request is re-injected into `mitmproxy` for a new attempt.
10. **Management UI**: `management_server.py` provides an interface to control the proxy, manage settings (keywords, blocklist), view stats, and monitor activity.

## Setup and Usage

### Prerequisites

* Python 3.8+
* `mitmproxy` (ensure `mitmdump` is in your system PATH)
* Other dependencies (Flask, pandas, scikit-learn, requests etc. - see `requirements.txt` if available, or install manually).

### Installation

1.  **Clone the Repository** (or set up your project files).
2.  **Create and Activate a Virtual Environment** (recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Linux/macOS
    .\venv\Scripts\activate    # On Windows
    ```
3.  **Install Dependencies**:
    ```bash
    pip install mitmproxy flask pandas scikit-learn requests beautifulsoup4 joblib
    # (Or use pip install -r requirements.txt if provided)
    ```
4.  **Configure `config.py`**:
    * Review paths like `MITMPROXY_CERT_DIR`. It's recommended to have a local `mitmproxy_certs` directory in your project root for mitmproxy's configuration and certificates.
    * The `DNS_BLOCKLIST_URL` is pre-configured but can be changed.
    * Adjust `MITMPROXY_LISTEN_HOST`, `MITMPROXY_LISTEN_PORT`, `MANAGEMENT_SERVER_PORT` if needed.

### Running the System

1.  **Start the Management UI Server**:
    ```bash
    python management_server.py
    ```
    * Access the UI in your browser, typically at `http://127.0.0.1:8000`.
    * On first startup, it will attempt to download the DNS blocklist specified in `config.py`.

2.  **From the Management UI**:
    * Click **"Start Proxy"**. This will attempt to run `mitmdump` with your `main.py` script.
    * The UI will guide you to download and install the **mitmproxy CA certificate**. This is a **crucial manual step** for HTTPS interception. Follow the detailed instructions provided in the UI for your specific OS/browser.
    * Configure your browser or system to use the proxy settings displayed in the UI (e.g., Host: `127.0.0.1`, Port: `8081`).

3.  **Monitor and Manage**:
    * Use the UI to view live logs (including mitmproxy console output).
    * Manage HTML rating keywords and their scores.
    * Manage the DNS blocklist (add/remove/refresh).
    * View site statistics.

### Directory Structure (Simplified)