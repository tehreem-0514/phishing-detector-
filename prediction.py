# feature_predictor.py
import re
import os
import time
import ssl
import socket
import joblib
import whois
import dns.resolver
import requests
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote
from collections import OrderedDict
import math
from dotenv import load_dotenv
from phishing_agent import run_phishing_agent


# Load environment variables early
load_dotenv()
API_KEY = os.getenv("API_KEY")
CSE_ID = os.getenv("CSE_ID")

# Suspicious/high-risk file extensions (kept for offline checks but NOT part of FEATURE_ORDER)
SUSPICIOUS_EXTENSIONS = {".exe", ".zip", ".scr", ".bat", ".cmd", ".js", ".jar", ".vbs", ".ps1", ".apk"}

# ---------------------------
# Config / filenames
# ---------------------------
SCALER_PATH = "scaler.pkl"
MODEL_PATH = "best_model.pkl"

# Attempt to load scaler & model (fail clearly if missing)
try:
    scaler = joblib.load(SCALER_PATH)
except Exception as e:
    raise RuntimeError(f"Failed to load scaler from {SCALER_PATH}: {e}")

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    raise RuntimeError(f"Failed to load model from {MODEL_PATH}: {e}")

# Short URL domains list (expandable)
SHORT_URL_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bit.do", "cutt.ly", "tiny.cc"
}

# ---------------------------
# Utility functions
# ---------------------------
def normalize_input_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(normalize_input_url(url))
        host = parsed.netloc or parsed.path
        # remove credentials if present
        if "@" in host:
            host = host.split("@")[-1]
        return host.lower()
    except Exception:
        return ""

def is_ip_address(s: str) -> bool:
    try:
        # only check bare IPv4
        parts = s.split(":")[0]  # strip port
        socket.inet_aton(parts)
        return True
    except Exception:
        return False

def safe_int(v, default=-1):
    try:
        return int(v)
    except Exception:
        return default

# ---------------------------
# Structural / string features
# ---------------------------
def count_char(s: str, ch: str):
    return (s or "").count(ch)

def count_chars(s: str, chars):
    return sum((s or "").count(c) for c in chars)

def get_path_and_file_and_params(url: str):
    parsed = urlparse(normalize_input_url(url))
    path = parsed.path or ""
    parts = path.split("/")
    directories = [p for p in parts[:-1] if p != ""]
    file_part = parts[-1] if parts and parts[-1] != "" else ""
    params = parsed.query or ""
    return directories, file_part, params

def count_params(params: str):
    if not params:
        return 0
    return len(parse_qs(params, keep_blank_values=True))

# ---------------------------
# Network / external helpers
# ---------------------------
def get_time_response(url):
    try:
        start = time.time()
        with urllib.request.urlopen(normalize_input_url(url), timeout=8) as response:
            _ = response.read(1024)
        end = time.time()
        return float(end - start)
    except Exception:
        return -1.0

def get_asn_ip(url):
    try:
        domain = extract_domain(url).split(":")[0]
        ip_address = socket.gethostbyname(domain)
        ip_parts = ip_address.split(".")
        asn_value = sum(int(part) * (256 ** i) for i, part in enumerate(reversed(ip_parts)))
        return asn_value
    except Exception:
        return -1

def get_domain_whois_features(url):
    res = {"time_domain_activation": -1, "time_domain_expiration": -1, "domain_age_days": -1}
    try:
        domain = extract_domain(url).lstrip("www.")
        if not domain:
            return res
        w = whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date

        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiration, list):
            expiration = expiration[0]

        if creation:
            try:
                res["time_domain_activation"] = int(creation.timestamp())
            except Exception:
                res["time_domain_activation"] = -1

        if expiration:
            try:
                res["time_domain_expiration"] = int(expiration.timestamp())
            except Exception:
                res["time_domain_expiration"] = -1

        if creation and expiration:
            try:
                days = (expiration - creation).days
                res["domain_age_days"] = int(days)
            except Exception:
                res["domain_age_days"] = -1
    except Exception:
        # WHOIS commonly fails in cloud environments; keep defaults
        pass
    return res

def check_ssl(url: str) -> int:
    try:
        nurl = normalize_input_url(url)
        parsed = urlparse(nurl)
        hostname = parsed.hostname
        if hostname is None:
            return -1
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return 1
        except ssl.SSLError:
            return 0
        except Exception:
            return -1
    except Exception:
        return -1

def get_qty_nameservers(url):
    try:
        domain = extract_domain(url).lstrip("www.")
        answers = dns.resolver.resolve(domain, 'NS', lifetime=5)
        return len(answers)
    except Exception:
        return -1

def get_ttl_hostname(url):
    try:
        domain = extract_domain(url).lstrip("www.")
        answers = dns.resolver.resolve(domain, 'A', lifetime=5)
        return int(answers.rrset.ttl)
    except Exception:
        return -1

def get_mx_count(url):
    try:
        domain = extract_domain(url).lstrip("www.")
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        return len(answers)
    except Exception:
        return -1

def get_qty_redirects(url):
    try:
        norm = normalize_input_url(url)
        resp = requests.head(norm, timeout=8, allow_redirects=True)
        if len(resp.history) == 0 and resp.status_code == 405:
            resp = requests.get(norm, timeout=8, allow_redirects=True)
        return len(resp.history)
    except Exception:
        return -1

# ---------------------------
# Google Custom Search helpers (93/94)
# ---------------------------
def get_google_position(query_str, match_str):
    # Returns 1-based rank if found in items, otherwise -1.
    if not API_KEY or not CSE_ID:
        return -1
    try:
        encoded_query = requests.utils.requote_uri(query_str)
        search_url = (
            f"https://www.googleapis.com/customsearch/v1?"
            f"key={API_KEY}&cx={CSE_ID}&q={encoded_query}"
        )
        response = requests.get(search_url, timeout=10).json()
        items = response.get("items", [])
        if not items:
            return -1
        for index, item in enumerate(items, start=1):
            link = (item.get("link") or "").lower()
            if match_str.lower() in link:
                return index
        return -1
    except Exception:
        return -1

def is_shortened_url(url):
    try:
        n = normalize_input_url(url)
        parsed = urlparse(n)
        domain = parsed.netloc.lower().lstrip("www.")
        if domain in SHORT_URL_DOMAINS:
            return 1
        try:
            r = requests.head(n, allow_redirects=True, timeout=6)
            if len(r.history) > 0:
                return 1
        except Exception:
            return 0
    except Exception:
        return 0
    return 0

def contains_email_like(s: str) -> int:
    try:
        return 1 if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", s) else 0
    except Exception:
        return 0

def safe_float(v, default=-1.0):
    try:
        return float(v)
    except Exception:
        return default

# ---------------------------
# Main extraction (ensures exact order)
# ---------------------------
FEATURE_ORDER = [
"qty_dot_url","qty_hyphen_url","qty_underline_url","qty_slash_url","qty_questionmark_url",
"qty_equal_url","qty_at_url","qty_and_url","qty_exclamation_url","qty_space_url",
"qty_tilde_url","qty_comma_url","qty_plus_url","qty_asterisk_url","qty_hashtag_url",
"qty_dollar_url","qty_percent_url","qty_tld_url","length_url","qty_dot_domain",
"qty_underline_domain","qty_at_domain","qty_vowels_domain","domain_length","domain_in_ip",
"server_client_domain","qty_dot_directory","qty_hyphen_directory","qty_underline_directory","qty_slash_directory",
"qty_questionmark_directory","qty_equal_directory","qty_at_directory","qty_and_directory","qty_exclamation_directory",
"qty_space_directory","qty_tilde_directory","qty_comma_directory","qty_plus_directory","qty_asterisk_directory",
"qty_hashtag_directory","qty_dollar_directory","qty_percent_directory","directory_length","qty_dot_file",
"qty_hyphen_file","qty_underline_file","qty_slash_file","qty_questionmark_file","qty_equal_file",
"qty_at_file","qty_and_file","qty_exclamation_file","qty_space_file","qty_tilde_file",
"qty_comma_file","qty_plus_file","qty_asterisk_file","qty_hashtag_file","qty_dollar_file",
"qty_percent_file","file_length","qty_dot_params","qty_hyphen_params","qty_underline_params",
"qty_slash_params","qty_questionmark_params","qty_equal_params","qty_at_params","qty_and_params",
"qty_exclamation_params","qty_space_params","qty_tilde_params","qty_comma_params","qty_plus_params",
"qty_asterisk_params","qty_hashtag_params","qty_dollar_params","qty_percent_params","params_length",
"tld_present_params","qty_params","email_in_url","time_response","asn_ip","time_domain_activation",
"time_domain_expiration","qty_nameservers","qty_mx_servers","ttl_hostname","tls_ssl_certificate",
"qty_redirects","url_google_index","domain_google_index","url_shortened","domain_age_days",
"dots_per_domain","vowels_ratio_domain","qty_dot_url_ratio"
]

def extract_all_features(url: str) -> OrderedDict:
    url_original = (url or "").strip()
    url = normalize_input_url(url_original)
    domain = extract_domain(url)
    parsed = urlparse(url)
    path = parsed.path or ""
    query = parsed.query or ""
    host = parsed.netloc or parsed.path

    features = OrderedDict()

    directories, file_part, params = get_path_and_file_and_params(url)
    dir_str = "/".join(directories)
    file_str = file_part or ""

    # --- 1-17: counts in URL
    features["qty_dot_url"] = count_char(url_original, ".")
    features["qty_hyphen_url"] = count_char(url_original, "-")
    features["qty_underline_url"] = count_char(url_original, "_")
    features["qty_slash_url"] = count_char(url_original, "/")
    features["qty_questionmark_url"] = count_char(url_original, "?")
    features["qty_equal_url"] = count_char(url_original, "=")
    features["qty_at_url"] = count_char(url_original, "@")
    features["qty_and_url"] = count_char(url_original, "&")
    features["qty_exclamation_url"] = count_char(url_original, "!")
    features["qty_space_url"] = count_char(url_original, " ")
    features["qty_tilde_url"] = count_char(url_original, "~")
    features["qty_comma_url"] = count_char(url_original, ",")
    features["qty_plus_url"] = count_char(url_original, "+")
    features["qty_asterisk_url"] = count_char(url_original, "*")
    features["qty_hashtag_url"] = count_char(url_original, "#")
    features["qty_dollar_url"] = count_char(url_original, "$")
    features["qty_percent_url"] = count_char(url_original, "%")

    # 18 qty_tld_url
    tld_tokens = ['.com', '.net', '.org', '.edu', '.gov', '.io', '.co', '.info', '.biz', '.me']
    features["qty_tld_url"] = sum(url_original.lower().count(tok) for tok in tld_tokens)

    # 19 length_url
    features["length_url"] = len(url_original)

    # --- Domain-level counts
    domain_no_port = domain.split(":")[0]
    features["qty_dot_domain"] = count_char(domain_no_port, ".")
    features["qty_underline_domain"] = count_char(domain_no_port, "_")
    features["qty_at_domain"] = count_char(domain_no_port, "@")
    features["qty_vowels_domain"] = sum(1 for ch in domain_no_port if ch.lower() in "aeiou")
    features["domain_length"] = len(domain_no_port)
    features["domain_in_ip"] = 1 if is_ip_address(domain_no_port) else 0
    features["server_client_domain"] = 1 if re.search(r"(server|client)", domain_no_port) else 0

    # --- directory-level counts
    features["qty_dot_directory"] = count_char(dir_str, ".")
    features["qty_hyphen_directory"] = count_char(dir_str, "-")
    features["qty_underline_directory"] = count_char(dir_str, "_")
    features["qty_slash_directory"] = count_char(dir_str, "/")
    features["qty_questionmark_directory"] = count_char(dir_str, "?")
    features["qty_equal_directory"] = count_char(dir_str, "=")
    features["qty_at_directory"] = count_char(dir_str, "@")
    features["qty_and_directory"] = count_char(dir_str, "&")
    features["qty_exclamation_directory"] = count_char(dir_str, "!")
    features["qty_space_directory"] = count_char(dir_str, " ")
    features["qty_tilde_directory"] = count_char(dir_str, "~")
    features["qty_comma_directory"] = count_char(dir_str, ",")
    features["qty_plus_directory"] = count_char(dir_str, "+")
    features["qty_asterisk_directory"] = count_char(dir_str, "*")
    features["qty_hashtag_directory"] = count_char(dir_str, "#")
    features["qty_dollar_directory"] = count_char(dir_str, "$")
    features["qty_percent_directory"] = count_char(dir_str, "%")
    features["directory_length"] = len(dir_str)

    # --- file-level counts
    features["qty_dot_file"] = count_char(file_str, ".")
    features["qty_hyphen_file"] = count_char(file_str, "-")
    features["qty_underline_file"] = count_char(file_str, "_")
    features["qty_slash_file"] = count_char(file_str, "/")
    features["qty_questionmark_file"] = count_char(file_str, "?")
    features["qty_equal_file"] = count_char(file_str, "=")
    features["qty_at_file"] = count_char(file_str, "@")
    features["qty_and_file"] = count_char(file_str, "&")
    features["qty_exclamation_file"] = count_char(file_str, "!")
    features["qty_space_file"] = count_char(file_str, " ")
    features["qty_tilde_file"] = count_char(file_str, "~")
    features["qty_comma_file"] = count_char(file_str, ",")
    features["qty_plus_file"] = count_char(file_str, "+")
    features["qty_asterisk_file"] = count_char(file_str, "*")
    features["qty_hashtag_file"] = count_char(file_str, "#")
    features["qty_dollar_file"] = count_char(file_str, "$")
    features["qty_percent_file"] = count_char(file_str, "%")
    features["file_length"] = len(file_str)

    # --- params (query) level counts
    features["qty_dot_params"] = count_char(params, ".")
    features["qty_hyphen_params"] = count_char(params, "-")
    features["qty_underline_params"] = count_char(params, "_")
    features["qty_slash_params"] = count_char(params, "/")
    features["qty_questionmark_params"] = count_char(params, "?")
    features["qty_equal_params"] = count_char(params, "=")
    features["qty_at_params"] = count_char(params, "@")
    features["qty_and_params"] = count_char(params, "&")
    features["qty_exclamation_params"] = count_char(params, "!")
    features["qty_space_params"] = count_char(params, " ")
    features["qty_tilde_params"] = count_char(params, "~")
    features["qty_comma_params"] = count_char(params, ",")
    features["qty_plus_params"] = count_char(params, "+")
    features["qty_asterisk_params"] = count_char(params, "*")
    features["qty_hashtag_params"] = count_char(params, "#")
    features["qty_dollar_params"] = count_char(params, "$")
    features["qty_percent_params"] = count_char(params, "%")
    features["params_length"] = len(params)
    features["tld_present_params"] = 1 if re.search(r"\.[a-z]{2,}$", params) else 0
    features["qty_params"] = count_params(params)

    # email_in_url
    features["email_in_url"] = contains_email_like(url_original)

    # External/network features:
    features["time_response"] = safe_float(get_time_response(url))
    features["asn_ip"] = get_asn_ip(url)

    whois_feats = get_domain_whois_features(url)
    features["time_domain_activation"] = whois_feats.get("time_domain_activation", -1)
    features["time_domain_expiration"] = whois_feats.get("time_domain_expiration", -1)

    features["qty_nameservers"] = get_qty_nameservers(url)
    features["qty_mx_servers"] = get_mx_count(url)
    features["ttl_hostname"] = get_ttl_hostname(url)
    features["tls_ssl_certificate"] = check_ssl(url)
    features["qty_redirects"] = get_qty_redirects(url)

    # Use domain-based searches for Google positions (more reliable)
    domain_for_search = domain or extract_domain(url)
    url_idx = get_google_position(domain_for_search, url) if API_KEY and CSE_ID else -1
    domain_idx = get_google_position(domain_for_search, domain_for_search) if API_KEY and CSE_ID else -1
    features["url_google_index"] = url_idx
    features["domain_google_index"] = domain_idx

    features["url_shortened"] = is_shortened_url(url)

    # domain_age_days (may be present from whois)
    features["domain_age_days"] = whois_feats.get("domain_age_days", -1)

    # dots_per_domain, vowels_ratio_domain, qty_dot_url_ratio
    domain_len = features.get("domain_length", 0) or 1
    features["dots_per_domain"] = safe_float(features.get("qty_dot_domain", 0)) / domain_len

    vowels_dom = features.get("qty_vowels_domain", 0)
    features["vowels_ratio_domain"] = safe_float(vowels_dom) / (domain_len or 1)

    url_len = features.get("length_url", 0) or 1
    features["qty_dot_url_ratio"] = safe_float(features.get("qty_dot_url", 0)) / url_len

    # Ensure ordering and return (only features in FEATURE_ORDER are returned)
    ordered = OrderedDict()
    for feat in FEATURE_ORDER:
        ordered[feat] = features.get(feat, -1)
    return ordered

# ---------------------------
# Prediction wrapper that prints detailed output
# ---------------------------
from phishing_agent import run_phishing_agent


def predict_url(url: str):
    print("\n========== URL CLASSIFICATION ==========")
    print("URL:", url)

    features = extract_all_features(url)
    if len(features) != len(FEATURE_ORDER):
        print(f"Feature count mismatch: expected {len(FEATURE_ORDER)}, got {len(features)}")
        return None

    import pandas as pd

    # Convert to DataFrame with correct feature names
    X_df = pd.DataFrame([list(features.values())], columns=FEATURE_ORDER)

    # Scaling
    try:
        X_scaled = scaler.transform(X_df)
    except Exception as e:
        print("Error applying scaler:", e)
        X_scaled = X_df.values  # fallback

    # --- Model Prediction ---
    try:
        prob = model.predict_proba(X_scaled)[0, 1] if hasattr(model, "predict_proba") else None
        pred = model.predict(X_scaled)[0]
        prob_val = float(prob) if prob is not None else 0.0
    except Exception as e:
        print("Model prediction error:", e)
        prob_val = 0.0
        pred = -1

    # --- Alerts Logic ---
    alerts = []
    if features.get("tls_ssl_certificate", 0) == 0 and features.get("domain_age_days", 0) < 365*2:
        alerts.append("No SSL certificate detected (domain too new)")

    if (features.get("url_google_index", 0) <= 0 or features.get("domain_google_index", 0) <= 0) \
       and features.get("domain_age_days", 0) < 365*2:
        alerts.append("Google indexing missing (low trust domain)")

    if features.get("length_url", 0) > 200:
        alerts.append("Very long URL may be obfuscated")

    direct_suspicious = 0
    if features.get("email_in_url", 0) == 1:
        direct_suspicious = 1
    elif features.get("url_shortened", 0) == 1 and features.get("qty_redirects", 0) > 3:
        if features.get("domain_age_days", 0) < 365*2:
            direct_suspicious = 1

    # --- Final Decision Logic ---
    if alerts or direct_suspicious == 1:
        label = "PHISHING"
        prob_val = max(prob_val, 0.99)
    else:
        threshold = 0.85
        if features.get("domain_age_days", 0) > 365*2 and features.get("tls_ssl_certificate", 0) == 1:
            threshold = 0.98
        label = "PHISHING" if prob_val >= threshold else "SAFE"

    prob_text = f"{prob_val * 100:.2f}%" if prob is not None else "N/A"

    print(f"Prediction: {label} ({prob_text})")
    print("Feature Count:", len(features))

    if alerts:
        print("\n--- Suspicious Alerts ---")
        for alert in alerts:
            print("-", alert)

    print("\n--- Key Feature Insights ---")

    domain_activation = features.get("domain_age_days", "N/A")
    domain_expiration = features.get("days_domain_expiration", "N/A")
    google_url_index = features.get("url_google_index", "N/A")
    google_domain_index = features.get("domain_google_index", "N/A")

    print(f"{'Feature':<30} {'Value'}")
    print("-" * 50)
    print(f"{'Domain Active (days since)':<30} {domain_activation}")
    print(f"{'Domain Expiry (days until)':<30} {domain_expiration}")
    print(f"{'Google URL Index Pos':<30} {google_url_index}")
    print(f"{'Google Domain Index Pos':<30} {google_domain_index}")

    print("========================================\n")

    # ---------------------------------------------------------------------
    #                     LLM AGENT EXPLANATION SECTION
    # ---------------------------------------------------------------------
    try:
        llm_report = run_phishing_agent(
        url=url,
        features=features,
        prediction=label
    )

        print("\n========== LLM EXPLANATION REPORT ==========")
        print(llm_report)
        print("============================================\n")

    except Exception as e:
        print("\n[LLM ERROR] Could not fetch LLM explanation:", e)
        llm_report = None

    # ---------------------------------------------------------------------

    return {
        "url": url,
        "label": label,
        "probability": prob_val,
        "features_raw": features,
        "scaled_vector": X_scaled.tolist()[0],
        "alerts": alerts,
        "llm_report": llm_report
    }

if __name__ == "__main__":
    print("Enter URLs to check (type 'exit' to quit):")
    while True:
        u = input("URL → ").strip()
        if u.lower() in ("exit", "quit"):
            break
        predict_url(u)
