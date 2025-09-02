"""
vuln_app.py — Deliberately insecure sample for GitHub CodeQL

Includes examples of:
- CWE-089: SQL Injection
- CWE-078: OS Command Injection
- CWE-022: Path Traversal
- CWE-502: Insecure Deserialization (pickle)
- CWE-327: Weak Cryptographic Hash (MD5)
- CWE-338: Insecure Randomness
- CWE-915/CWE-94: Dangerous eval()
- CWE-295: Disabled TLS Verification (requests)
- CWE-798: Hardcoded credentials
- CWE-489: Debug mode enabled (Flask)
"""

import os
import sqlite3
import subprocess
import hashlib
import random
import pickle
from flask import Flask, request, send_file

# Optional: if 'requests' and 'PyYAML' are installed, these will be additional findings
try:
    import requests  # type: ignore
except Exception:
    requests = None

try:
    import yaml  # type: ignore
except Exception:
    yaml = None

app = Flask(__name__)

# --- Hardcoded credentials (CWE-798) ---
SECRET_KEY = "dev-secret-key-please-dont-use"          # hard-coded secret
DB_PASSWORD = "P@ssw0rd123"                            # hard-coded password
AWS_ACCESS_KEY_ID = "AKIA1234567890ABCD"               # looks like a key
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfi" # looks like a secret

DB_PATH = "app.db"
UPLOAD_DIR = "uploads"

def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)")
    conn.commit()
    conn.close()

@app.route("/search")
def search():
    # CWE-089: SQL Injection (user input interpolated directly)
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT id, name FROM users WHERE name = '{name}'"  # VULNERABLE
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return {"rows": rows, "query": query}

@app.route("/run")
def run():
    # CWE-078: Command Injection (shell=True + untrusted input)
    cmd = request.args.get("cmd", "ls")
    subprocess.call(cmd, shell=True)  # VULNERABLE
    return "OK"

@app.route("/upload", methods=["POST"])
def upload():
    # CWE-022: Path Traversal (unvalidated filename used to build path)
    filename = request.args.get("filename", "file.txt")
    path = os.path.join(UPLOAD_DIR, filename)  # VULNERABLE
    with open(path, "wb") as f:
        f.write(request.data)
    return {"saved": path}

@app.route("/download")
def download():
    # CWE-022: Path Traversal (read arbitrary path inside uploads)
    filename = request.args.get("filename", "")
    path = os.path.join(UPLOAD_DIR, filename)  # VULNERABLE
    return send_file(path)

@app.route("/token")
def token():
    # CWE-338: Insecure randomness for a “token”
    tok = "".join(str(random.randint(0, 9)) for _ in range(32))  # VULNERABLE
    return tok

@app.route("/hash")
def weak_hash():
    # CWE-327: Weak hash (MD5)
    pw = request.args.get("password", "password")
    return hashlib.md5(pw.encode()).hexdigest()  # VULNERABLE

@app.route("/calc")
def calc():
    # CWE-94/CWE-915: Dangerous eval
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))  # VULNERABLE

@app.route("/deserialize", methods=["POST"])
def deserialize():
    # CWE-502: Insecure deserialization (pickle)
    obj = pickle.loads(request.data)  # VULNERABLE
    return str(obj)

@app.route("/fetch")
def fetch():
    # CWE-295 (+ SSRF pattern): disabled TLS verification and user-controlled URL
    if requests is None:
        return "requests not installed"
    url = request.args.get("url", "https://example.com")
    r = requests.get(url, verify=False)  # VULNERABLE
    return r.text

@app.route("/yaml", methods=["POST"])
def yaml_load():
    # Unsafe YAML load (exec-capable) if PyYAML present
    if yaml is None:
        return "pyyaml not installed"
    data = yaml.load(request.data, Loader=yaml.Loader)  # VULNERABLE
    return str(data)

if __name__ == "__main__":
    init_db()
    # CWE-489: Flask debug mode enabled in production-like code
    app.run(host="0.0.0.0", port=5000, debug=True)  # VULNERABLE
