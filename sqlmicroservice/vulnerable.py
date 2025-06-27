import logging
from flask import Flask, request
import sqlite3

app = Flask(__name__)

# CSV-style logging
logging.basicConfig(
    filename='sql_logs.csv',
    level=logging.INFO,
    format='%(asctime)s,%(message)s',
)

@app.route('/login')
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    ip = request.remote_addr
    ua = request.headers.get('User-Agent')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print("[DEBUG] Executing:", query)

    try:
        cursor.execute(query)
        result = cursor.fetchone()
        status = "200 OK" if result else "401 Unauthorized"
    except sqlite3.Error as e:
        app.logger.error(f"SQL Error: {e}")
        status = "500 Internal Server Error"
        query = f"ERROR: {e}"
        result = None

    logging.info(f"{ip},GET,/login,{username},{password},{query},{status},{ua}")
    return "✅ Login Successful" if result else "❌ Login Failed", 200 if result else 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

