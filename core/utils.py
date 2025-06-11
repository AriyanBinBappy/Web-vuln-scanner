from urllib.parse import urlparse, parse_qs

def extract_params(url):
    return parse_qs(urlparse(url).query)
