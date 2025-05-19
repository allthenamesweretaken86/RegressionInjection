# utils.py
import json
import os
import time
import logging
import re
from urllib.parse import urlparse
import requests # For downloading the blocklist

from config import HTML_RATING_KEYWORDS_FILE, RATING_SCALE_MIN, RATING_SCALE_MAX

logger = logging.getLogger(__name__)

# --- Existing HTML Keyword Functions ---
html_keyword_scores = {}
HOST_LAST_REQUEST_TIME = {} # Moved here from function default for persistence across calls if utils is treated as a module instance by mitmproxy

def load_html_keywords():
    """Loads HTML rating keywords from the JSON file into memory."""
    global html_keyword_scores
    try:
        if os.path.exists(HTML_RATING_KEYWORDS_FILE):
            with open(HTML_RATING_KEYWORDS_FILE, 'r', encoding='utf-8') as f:
                html_keyword_scores = json.load(f)
            logger.info(f"Successfully loaded HTML rating keywords: {html_keyword_scores}")
        else:
            logger.warning(f"HTML keywords file not found: {HTML_RATING_KEYWORDS_FILE}. Using empty set.")
            html_keyword_scores = {}
    except Exception as e:
        logger.error(f"Error loading HTML keywords from {HTML_RATING_KEYWORDS_FILE}: {e}", exc_info=True)
        html_keyword_scores = {}
    return html_keyword_scores

def get_html_keywords():
    """Returns the currently loaded HTML keywords and their scores."""
    return html_keyword_scores.copy()

def update_html_keywords(new_keywords: dict) -> bool:
    """Updates the keywords in memory and saves them to the JSON file."""
    global html_keyword_scores
    try:
        # Validate scores are numbers
        for k, v in new_keywords.items():
            if not isinstance(v, (int, float)):
                raise ValueError(f"Score for keyword '{k}' must be a number, got '{v}'")
            html_keyword_scores[str(k).strip().lower()] = float(v) # Standardize key

        os.makedirs(os.path.dirname(HTML_RATING_KEYWORDS_FILE), exist_ok=True)
        with open(HTML_RATING_KEYWORDS_FILE, 'w', encoding='utf-8') as f:
            json.dump(html_keyword_scores, f, indent=4)
        logger.info(f"HTML rating keywords updated and saved to {HTML_RATING_KEYWORDS_FILE}")
        return True
    except ValueError as ve:
        logger.error(f"ValueError updating HTML keywords: {ve}")
        return False
    except Exception as e:
        logger.error(f"Error updating HTML keywords: {e}", exc_info=True)
        return False

# --- Existing Utility Functions ---
def calculate_time_since_last_request(url: str) -> float:
    """Calculates time since the last request to the same host."""
    global HOST_LAST_REQUEST_TIME
    host = urlparse(url).netloc
    current_time = time.time()
    time_since = current_time - HOST_LAST_REQUEST_TIME.get(host, current_time) # Default to 0 for first request
    HOST_LAST_REQUEST_TIME[host] = current_time
    return round(time_since, 3)

def convert_bytes_to_str(value: bytes, encoding='utf-8', errors='replace') -> str:
    """Safely decodes bytes to string."""
    if isinstance(value, bytes):
        return value.decode(encoding, errors=errors)
    return str(value)

def normalize_score(score: float, min_val: float = 0, max_val: float = 10) -> float:
    """Clips a score to be within a defined min/max range."""
    return max(min_val, min(max_val, score))

def rate_response(status_code: int, html_content: str = None, base_score_map: dict = None) -> tuple[float, float | None, float]:
    """
    Rates a response based on status code and HTML content.
    Returns: (final_rating, dominant_keyword_score, html_length_score)
    Dominant_keyword_score is the direct score if a keyword dictates it, else None.
    """
    # Default base scores for HTTP status codes (0-10 scale)
    if base_score_map is None:
        base_score_map = {
            200: 8.0, 201: 7.5, 202: 7.0, 204: 6.0, # Success
            301: 5.0, 302: 4.5, 304: 6.5, # Redirection / Not Modified (often okay)
            400: 2.0, 401: 1.5, 403: 1.0, 404: 0.5, # Client errors
            500: 0.2, 502: 0.1, 503: 0.3, 504: 0.0  # Server errors
        }

    # Start with a base score from the status code
    current_rating = base_score_map.get(status_code, 2.0 if 400 <= status_code < 500 else 0.0) # Default for unlisted client/server errors

    # HTML Content Analysis
    html_length_score = 0.0
    dominant_keyword_score = None # This will hold the score if a keyword directly dictates the rating

    if html_content and isinstance(html_content, str):
        html_lower = html_content.lower()
        # HTML Length Score (simple version, up to 2 points)
        length = len(html_lower)
        if length > 10000: html_length_score = 2.0
        elif length > 5000: html_length_score = 1.5
        elif length > 1000: html_length_score = 1.0
        elif length > 200: html_length_score = 0.5
        else: html_length_score = 0.1 # Small penalty for very short HTML unless it's an error page

        # Keyword Scoring
        # If html_keyword_scores is empty, load them
        if not html_keyword_scores and os.path.exists(HTML_RATING_KEYWORDS_FILE):
            load_html_keywords()

        for keyword, score_effect in html_keyword_scores.items():
            if keyword in html_lower:
                logger.debug(f"Keyword '{keyword}' found. Applying score effect: {score_effect}")
                # If score_effect implies a direct rating (e.g. a captcha keyword sets rating to 0.5)
                # We can define a threshold or a way to signify direct rating.
                # For now, let's assume if score_effect is low (e.g. < 3), it's a strong negative indicator.
                # If a keyword is meant to directly SET the score, it should be handled specially.
                # Let's assume keywords with scores like 0.5, 1.0 are meant to be direct and final if found.
                if score_effect <= RATING_SCALE_MAX / 2 and score_effect < current_rating : # Check if it should override
                     if dominant_keyword_score is None or score_effect < dominant_keyword_score:
                        dominant_keyword_score = score_effect # This keyword provides the dominant score

                # If not a dominant override, adjust current rating or add to length score
                # This part can be complex. Let's simplify: if a keyword has a high score, it adds to base.
                # If it has a low score, and no dominant score yet, it might pull down.
                # For the example, we'll let dominant_keyword_score take precedence if set.
                # Otherwise, add positive keyword scores and html_length_score
                elif score_effect > RATING_SCALE_MAX / 2: # Positive keyword
                    current_rating = max(current_rating, score_effect) # Take the highest positive indication
                # Negative keywords are handled by `dominant_keyword_score` if they are very low.
                # Other adjustments can be made here.

    if dominant_keyword_score is not None:
        final_rating = dominant_keyword_score
        logger.debug(f"Final rating determined by dominant keyword: {final_rating}")
    else:
        # If no dominant keyword dictated the score, combine base with length score.
        # Add positive keyword influences if they were stronger than base.
        final_rating = current_rating + html_length_score
        logger.debug(f"Calculated rating (base+length+positive_keywords): {final_rating}, from base: {current_rating}, length_score: {html_length_score}")

    final_normalized_rating = normalize_score(final_rating, RATING_SCALE_MIN, RATING_SCALE_MAX)
    logger.info(f"Rated URL (Status: {status_code}): Final Score = {final_normalized_rating:.2f} (DominantKeywordScore: {dominant_keyword_score}, HTMLLengthScore: {html_length_score:.2f})")
    return final_normalized_rating, dominant_keyword_score, html_length_score

# --- NEW DNS Blocklist Functions ---

def get_domain_from_url(request_url: str) -> str | None:
    """Extracts the domain (netloc) from a URL."""
    try:
        parsed_url = urlparse(request_url)
        return parsed_url.netloc.lower()
    except Exception as e:
        logger.error(f"Error parsing domain from URL '{request_url}': {e}")
        return None

def is_valid_domain(domain: str) -> bool:
    """Basic validation for domain format."""
    if not domain or not isinstance(domain, str):
        return False
    # Regex for basic domain validation (simplified)
    # Allows for subdomains, ASCII characters, numbers, and hyphens.
    # Does not validate TLD existence or full RFC compliance.
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)'  # Subdomain
        r'+[a-zA-Z0-9][a-zA-Z0-9-_]{0,61}[a-zA-Z0-9]$'  # TLD
    )
    return bool(domain_regex.match(domain))


def download_blocklist(url: str, local_path: str) -> bool:
    """Downloads the blocklist from the URL and saves it locally."""
    try:
        logger.info(f"Attempting to download blocklist from: {url}")
        response = requests.get(url, timeout=30) # 30-second timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4XX or 5XX)

        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        logger.info(f"Successfully downloaded and saved blocklist to: {local_path}")
        return True
    except requests.exceptions.Timeout:
        logger.error(f"Timeout while trying to download blocklist from {url}.")
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred while downloading blocklist: {http_err} (URL: {url})")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"Error downloading blocklist from {url}: {req_err}")
    except IOError as io_err:
        logger.error(f"IOError saving blocklist to {local_path}: {io_err}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during blocklist download: {e}", exc_info=True)
    return False

def load_blocklist(path: str) -> set:
    """Loads the blocklist from a local file into a set of domains."""
    blocked_domains = set()
    if not os.path.exists(path):
        logger.warning(f"Blocklist file not found at {path}. Returning empty set.")
        return blocked_domains
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, 1):
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#') or line.startswith('!'):
                    continue
                # Basic domain parsing: take the first part if line contains IP + domain
                # e.g., "0.0.0.0 example.com" -> "example.com"
                parts = line.split()
                domain_candidate = parts[-1] # Assume domain is the last part

                if is_valid_domain(domain_candidate):
                    blocked_domains.add(domain_candidate.lower())
                else:
                    logger.debug(f"Skipping invalid domain entry '{domain_candidate}' from blocklist file '{path}' at line {line_number}.")
        logger.info(f"Loaded {len(blocked_domains)} domains from blocklist: {path}")
    except Exception as e:
        logger.error(f"Error loading blocklist from {path}: {e}", exc_info=True)
    return blocked_domains

def is_url_blocked(request_url: str, blocklist_set: set) -> bool:
    """Checks if the domain of the request_url is in the blocklist_set."""
    if not blocklist_set: # If the blocklist is empty, nothing is blocked
        return False
    domain = get_domain_from_url(request_url)
    if not domain:
        return False # Cannot determine domain, treat as not blocked for safety

    # Direct match
    if domain in blocklist_set:
        return True

    # Check for subdomain blocking (e.g., if "example.com" is in list, block "sub.example.com")
    # This requires iterating and checking parts of the domain.
    # The Hagezi lists are usually specific, so direct match is often sufficient.
    # For more comprehensive matching:
    # parts = domain.split('.')
    # for i in range(len(parts)):
    #     sub_domain = '.'.join(parts[i:])
    #     if sub_domain in blocklist_set:
    #         return True
    return False

def add_domain_to_blocklist(domain: str, file_path: str, blocklist_set: set) -> bool:
    """Adds a domain to the local blocklist file and the in-memory set."""
    domain = domain.strip().lower()
    if not is_valid_domain(domain):
        logger.warning(f"Attempted to add invalid domain to blocklist: {domain}")
        return False
    try:
        # Add to file (append a new line)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(f"\n# User added: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{domain}\n")

        # Add to in-memory set
        blocklist_set.add(domain)
        logger.info(f"Domain '{domain}' added to local blocklist file and in-memory set.")
        return True
    except Exception as e:
        logger.error(f"Error adding domain '{domain}' to blocklist: {e}", exc_info=True)
        return False

def remove_domain_from_blocklist(domain_to_remove: str, file_path: str, blocklist_set: set) -> bool:
    """Removes a domain from the local blocklist file and the in-memory set."""
    domain_to_remove = domain_to_remove.strip().lower()
    if not is_valid_domain(domain_to_remove):
        logger.warning(f"Attempted to remove invalid domain from blocklist: {domain_to_remove}")
        return False

    if not os.path.exists(file_path):
        logger.warning(f"Cannot remove '{domain_to_remove}': blocklist file '{file_path}' not found.")
        if domain_to_remove in blocklist_set: # Also remove from set if present
             blocklist_set.discard(domain_to_remove)
        return False

    lines_kept = []
    found = False
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                # Check if this line contains the domain to remove
                # Simple check: if the domain is the last part of the line (e.g., after an IP) or the only part
                parts = stripped_line.split()
                if parts and parts[-1].lower() == domain_to_remove:
                    found = True
                    logger.debug(f"Removing line containing '{domain_to_remove}' from '{file_path}': {line.strip()}")
                    # Also remove any comment line immediately preceding it if it's a "User added" comment
                    if lines_kept and lines_kept[-1].strip().startswith("# User added"):
                        potential_comment = lines_kept.pop().strip()
                        logger.debug(f"Also removing preceding comment: {potential_comment}")
                    continue # Skip this line
                lines_kept.append(line)

        if found:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines_kept)
            logger.info(f"Domain '{domain_to_remove}' removed from local blocklist file.")
        else:
            logger.info(f"Domain '{domain_to_remove}' not found in blocklist file '{file_path}'.")

        # Remove from in-memory set regardless of file presence (could have been added to set only)
        if domain_to_remove in blocklist_set:
            blocklist_set.discard(domain_to_remove)
            logger.info(f"Domain '{domain_to_remove}' removed from in-memory set.")
            found = True # Ensure it's true if removed from set

        return found
    except Exception as e:
        logger.error(f"Error removing domain '{domain_to_remove}' from blocklist: {e}", exc_info=True)
        return False