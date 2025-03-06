httpInjection
An intelligent HTTP proxy system with machine learning-based request optimization and caching.
Overview
httpInjection is a proxy tool built on mitmproxy that intelligently handles HTTP requests with advanced features:

Machine Learning Optimization: Learns successful request patterns to improve retry success rates
Smart Caching: Efficiently caches and serves responses to reduce latency and server load
Automatic Retry Management: Intelligently retries failed requests with optimized headers
Performance Monitoring: Tracks metrics like response times, cache hits/misses, and error rates

The system uses scikit-learn's LogisticRegression model to analyze HTTP request patterns and determine which combinations of headers and parameters lead to successful responses.
Architecture
Show Image
The system consists of several key components:

Proxy Controller: Manages the interception and processing of HTTP requests
Cache System: Stores and retrieves cached responses
Machine Learning Engine: Analyzes request patterns and predicts optimal configurations
Retry Manager: Handles failed requests with intelligent retry strategies
Monitoring System: Tracks performance metrics and errors

Installation
Prerequisites

Python 3.8+
mitmproxy 8.0+
pandas
scikit-learn
numpy

Setup

Clone the repository:
bashCopygit clone https://github.com/yourusername/httpInjection.git
cd httpInjection

Install dependencies:
bashCopypip install -r requirements.txt

Configure the proxy settings in config.py if needed.
Generate mitmproxy certificates (if not already available):
bashCopymkdir -p mitmproxy
mitmdump --set confdir=./mitmproxy


Usage
Start the proxy with:
bashCopymitmdump --set client_certs=mitmproxy/chain-ca.pem --set upstream_cert=false --mode upstream:http://<upstream-proxy-ip>:<port> --set block_global=false --listen-port 8081 -s main.py --ssl-insecure
Replace <upstream-proxy-ip> and <port> with your upstream proxy details, or remove the --mode upstream:... part to use direct connections.
Configuration Options
Edit config.py to configure:

Cache settings: Directory locations, expiry times, maximum size
Model parameters: Training samples required, retraining intervals
Retry parameters: Maximum retries, delay strategies

How It Works
Machine Learning Model
The system uses a supervised learning approach:

Data Collection: Records features from HTTP requests and their responses
Feature Engineering: Extracts meaningful patterns from headers, timing, and response codes
Model Training: Periodically trains a LogisticRegression model on successful patterns
Prediction: Uses the model to optimize retry attempts for failed requests

Caching Strategy
The caching system:

Stores responses with appropriate expiry times
Handles binary content appropriately
Maintains cache size limits with least-recently-used eviction
Preserves header information for accurate response recreation

Retry Management
When a request fails:

The system analyzes the failure pattern
Retrieves successful patterns for similar requests
Applies intelligent modifications to headers and parameters
Schedules retries with exponential backoff
Records outcomes to improve future optimizations

Performance Monitoring
The system tracks:

Request/response counts and timings
Cache hit/miss rates
Error types and frequencies
Retry success rates
Model training metrics

License
This project is licensed under the MIT License - see the LICENSE file for details.
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
Acknowledgements

mitmproxy - The powerful HTTP proxy tool
scikit-learn - Machine learning framework
pandas - Data manipulation and analysis
