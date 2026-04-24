import json

EXPORTED_REQUESTS = []

def log_request(request_data):
    print("LOGGING REQUEST:", request_data)  # 👈 debug
    EXPORTED_REQUESTS.append(request_data)

    

# 🔥 conversion JSON → RAW HTTP
def to_raw_http(req):
    method = req.get("method", "GET")
    url = req.get("url", "/")
    headers = req.get("headers", {})
    body = req.get("body", "")

    # Check if this is a POST to /api/v1/detect (internal API call)
    if method.upper() == "POST" and url == "/api/v1/detect" and body:
        try:
            # Parse the inner request from the JSON body
            inner_req = json.loads(body)
            # Extract the actual user request
            method = inner_req.get("method", "GET").upper()
            url = inner_req.get("url", "/")
            headers = inner_req.get("headers", {})
            body = inner_req.get("body", "")
        except (json.JSONDecodeError, KeyError):
            # If parsing fails, use the original request
            pass

    # ligne principale
    raw = f"{method} {url} HTTP/1.1\n"

    # Add Host header
    raw += "Host: testserver\n"

    # Add Content-Type if there's a body
    if body:
        raw += "Content-Type: application/json\n"

    # Add other headers (skip host and content-type as we handle them above)
    for k, v in headers.items():
        if k.lower() not in ("host", "content-type"):
            raw += f"{k}: {v}\n"

    # ligne vide avant body
    raw += "\n"

    # body si existe
    if body:
        raw += body

    return raw

# 💾 sauvegarde JSON
def save_requests_json(file="exported_requests.json"):
    with open(file, "w") as f:
        json.dump(EXPORTED_REQUESTS, f, indent=2)

# 💾 sauvegarde RAW HTTP
def save_requests_raw(file="exported_requests.txt"):
    with open(file, "w") as f:
        for req in EXPORTED_REQUESTS:
            raw = to_raw_http(req)
            f.write(raw)
            f.write("\n\n### --- ###\n\n")  # séparateur

def save_requests():
    save_requests_json()
    save_requests_raw()