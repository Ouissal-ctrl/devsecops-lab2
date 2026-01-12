from flask import Flask, request, jsonify
import sqlite3
import subprocess
import hashlib
import os
import hmac
import secrets

app = Flask(__name__)

# =====================
# CONFIGURATION SECURISEE
# =====================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DATABASE = 'users.db'
BASE_DIR = os.path.abspath('.')

# =====================
# UTILITAIRES
# =====================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    """Hash sécurisé (SHA-256 + salt simple)"""
    salt = 'static_salt_for_demo'  # pour TP seulement
    return hashlib.sha256((password + salt).encode()).hexdigest()


# =====================
# ROUTES
# =====================

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    username = data.get('username', '')
    password = data.get('password', '')

    conn = get_db()
    cursor = conn.cursor()

    # Requête préparée (ANTI SQL INJECTION)
    cursor.execute(
        'SELECT username, password FROM users WHERE username = ? AND password = ?',
        (username, hash_password(password))
    )

    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({'status': 'success', 'user': username})
    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401


@app.route('/ping', methods=['POST'])
def ping():
    data = request.get_json(force=True)
    host = data.get('host', '')

    # Validation simple
    if not host.isalnum():
        return jsonify({'error': 'Invalid host'}), 400

    try:
        result = subprocess.run(
            ['ping', '-c', '1', host],
            capture_output=True,
            text=True,
            timeout=5
        )
        return jsonify({'output': result.stdout})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/compute', methods=['POST'])
def compute():
    data = request.get_json(force=True)
    expression = data.get('expression', '1+1')

    # Calcul sécurisé : uniquement opérations math simples
    allowed = set('0123456789+-*/(). ')
    if not set(expression).issubset(allowed):
        return jsonify({'error': 'Invalid expression'}), 400

    try:
        result = eval(expression, {'__builtins__': None}, {})
        return jsonify({'result': result})
    except Exception:
        return jsonify({'error': 'Computation error'}), 400


@app.route('/hash', methods=['POST'])
def hash_api():
    data = request.get_json(force=True)
    pwd = data.get('password', '')
    return jsonify({'sha256': hash_password(pwd)})


@app.route('/readfile', methods=['POST'])
def readfile():
    data = request.get_json(force=True)
    filename = data.get('filename', '')

    # Protection contre Path Traversal
    safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))
    if not safe_path.startswith(BASE_DIR):
        return jsonify({'error': 'Access denied'}), 403

    try:
        with open(safe_path, 'r') as f:
            return jsonify({'content': f.read()})
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404


@app.route('/debug', methods=['GET'])
def debug():
    # Debug désactivé en production
    return jsonify({'debug': False}), 403


@app.route('/hello', methods=['GET'])
def hello():
    return jsonify({'message': 'Welcome to the secured DevSecOps API'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
