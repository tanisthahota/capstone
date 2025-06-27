import logging
from flask import Flask, request
import sqlite3

app = Flask(__name__)
logging.basicConfig(
    filename='sql_logs.csv',
    level=logging.INFO,
    format='%(asctime)s,%(message)s',
)
@app.route('/login')
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # ❗ Vulnerable to SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print("[DEBUG] Executing:", query)

    cursor.execute(query)
    result = cursor.fetchone()
    logging.info(f"{ip},{request.method},{request.path},{username},{password},{query},{status},{ua}")
    return "✅ Login Successful" if result else "❌ Login Failed"
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
