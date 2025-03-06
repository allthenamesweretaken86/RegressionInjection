# httpInjection

An intelligent HTTP proxy system with machine learning-based request optimization and caching.

## Overview

httpInjection is a proxy tool built on mitmproxy that intelligently handles HTTP requests with advanced features:

- **Machine Learning Optimization**: Learns successful request patterns to improve retry success rates
- **Smart Caching**: Efficiently caches and serves responses to reduce latency and server load
- **Automatic Retry Management**: Intelligently retries failed requests with optimized headers
- **Performance Monitoring**: Tracks metrics like response times, cache hits/misses, and error rates

The system uses scikit-learn's LogisticRegression model to analyze HTTP request patterns and determine which combinations of headers and parameters lead to successful responses.

## Architecture

![Architecture Diagram](https://via.placeholder.com/800x400?text=httpInjection+Architecture)

The system consists of several key components:

- **Proxy Controller**: Manages the interception and processing of HTTP requests
- **Cache System**: Stores and retrieves cached responses
- **Machine Learning Engine**: Analyzes request patterns and predicts optimal configurations
- **Retry Manager**: Handles failed requests with intelligent retry strategies
- **Monitoring System**: Tracks performance metrics and errors

## Installation

### Prerequisites

- Python 3.8+
- mitmproxy 8.0+
- pandas
- scikit-learn
- numpy

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/httpInjection.git
   cd httpInjection
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure the proxy settings in `config.py` if needed.

4. Generate mitmproxy certificates (if not already available):
   ```bash
   mkdir -p mitmproxy
   mitmdump --set confdir=./mitmproxy
   ```

## Usage

Start the proxy with:

```bash
mitmdump --set client_certs=mitmproxy/chain-ca.pem --set upstream_cert=false --mode upstream:http://<upstream-proxy-ip>:<port> --set block_global=false --listen-port 8081 -s main.py --ssl-insecure
```

Replace `<upstream-proxy-ip>` and `<port>` with your upstream proxy details, or remove the `--mode upstream:...` part to use direct connections.

### Configuration Options

Edit `config.py` to configure:

- **Cache settings**: Directory locations, expiry times, maximum size
- **Model parameters**: Training samples required, retraining intervals
- **Retry parameters**: Maximum retries, delay strategies

## How It Works

### Machine Learning Model

The system uses a supervised learning approach:

1. **Data Collection**: Records features from HTTP requests and their responses
2. **Feature Engineering**: Extracts meaningful patterns from headers, timing, and response codes
3. **Model Training**: Periodically trains a LogisticRegression model on successful patterns
4. **Prediction**: Uses the model to optimize retry attempts for failed requests

### Caching Strategy

The caching system:

1. Stores responses with appropriate expiry times
2. Handles binary content appropriately
3. Maintains cache size limits with least-recently-used eviction
4. Preserves header information for accurate response recreation

### Retry Management

When a request fails:

1. The system analyzes the failure pattern
2. Retrieves successful patterns for similar requests
3. Applies intelligent modifications to headers and parameters
4. Schedules retries with exponential backoff
5. Records outcomes to improve future optimizations

## Performance Monitoring

The system tracks:

- Request/response counts and timings
- Cache hit/miss rates
- Error types and frequencies
- Retry success rates
- Model training metrics

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

- [mitmproxy](https://mitmproxy.org/) - The powerful HTTP proxy tool
- [scikit-learn](https://scikit-learn.org/) - Machine learning framework
- [pandas](https://pandas.pydata.org/) - Data manipulation and analysis

To start run command: mitmdump --set client_certs=mitmproxy/chain-ca.pem --set upstream_cert=false --mode upstream:http://192.168.1.123:3129 --set block_global=false --listen-port 8081 -s main.py --ssl-insecure
