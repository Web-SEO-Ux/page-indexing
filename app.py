from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import json
import time
import jwt
import urllib.request
import urllib.parse
from urllib.error import HTTPError
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

KEYS_DIRECTORY = 'api_keys'

def init_db():
    conn = sqlite3.connect('indexing_app.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS url_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        url TEXT NOT NULL,
                        status TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

init_db()

def get_access_token(credentials_file):
    with open(credentials_file, 'r') as f:
        credentials = json.load(f)

    current_time = int(time.time())
    jwt_payload = {
        "iss": credentials['client_email'],
        "scope": "https://www.googleapis.com/auth/indexing",
        "aud": "https://accounts.google.com/o/oauth2/token",
        "exp": current_time + 3600,
        "iat": current_time
    }
    jwt_token = jwt.encode(jwt_payload, credentials['private_key'], algorithm='RS256')

    token_data = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': jwt_token
    }
    token_data_encoded = urllib.parse.urlencode(token_data).encode('utf-8')
    token_request = urllib.request.Request(
        'https://accounts.google.com/o/oauth2/token', 
        data=token_data_encoded, 
        method='POST'
    )
    with urllib.request.urlopen(token_request) as token_response:
        token_response_data = token_response.read().decode('utf-8')
        return json.loads(token_response_data)['access_token']

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    api_keys = [f for f in os.listdir(KEYS_DIRECTORY) if f.endswith('.json')]
    return render_template('index.html', api_keys=api_keys)

@app.route('/logs')
def logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('indexing_app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT url, status, timestamp FROM url_logs WHERE user_id = ?", (user_id,))
    url_logs = cursor.fetchall()
    conn.close()

    return render_template('logs.html', url_logs=url_logs)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        conn = sqlite3.connect('indexing_app.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return 'Username already exists'
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('indexing_app.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        else:
            return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/index_urls', methods=['POST'])
def index_urls():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    selected_key = request.form['api_key']
    urls = request.form['urls'].splitlines()
    access_token = get_access_token(os.path.join(KEYS_DIRECTORY, selected_key))
    user_id = session['user_id']
    responses = []

    conn = sqlite3.connect('indexing_app.db')
    cursor = conn.cursor()

    for url in urls:
        payload = {"url": url.strip(), "type": "URL_UPDATED"}
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        payload_encoded = json.dumps(payload).encode('utf-8')

        try:
            req = urllib.request.Request(
                'https://indexing.googleapis.com/v3/urlNotifications:publish',
                data=payload_encoded,
                headers=headers,
                method='POST'
            )
            with urllib.request.urlopen(req) as response:
                response_data = response.read().decode('utf-8')
                status = json.loads(response_data).get('urlNotificationMetadata', {}).get('latestUpdate', {}).get('status')
                responses.append({"url": url.strip(), "success": True, "message": f"Indexed - Status: {status}"})

                cursor.execute("INSERT INTO url_logs (user_id, url, status) VALUES (?, ?, ?)", (user_id, url.strip(), status))
                conn.commit()

        except HTTPError as e:
            responses.append({"url": url.strip(), "success": False, "message": str(e)})

    conn.close()
    return jsonify(responses)

if __name__ == '__main__':
    app.run(debug=True)