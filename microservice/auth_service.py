# auth_service.py
from flask import Flask, request, jsonify
import time
import logging
import os

# Ensure log directory
import os
import logging

log_file_path = '/app/auth_logs.log'  # matches the mount target

logging.basicConfig(
    filename=log_file_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    start_time = time.time()
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    
    if username == "admin" and password == "password":
        logging.info(f"Successful login for {username}")
        response = jsonify({"message": "Login successful"})
        response.status_code = 200
    else:
        logging.warning(f"Failed login attempt for {username}")
        response = jsonify({"message": "Login failed"})
        response.status_code = 401

    duration = time.time() - start_time
    logging.info(f"Request processed in {duration:.4f} seconds")
    return response

@app.route('/dos', methods=['GET'])
def dos_vulnerable():
    a = [0] * (10**7)  # Allocate memory
    for _ in range(10**6):  # Simulate CPU work
        pass
    return jsonify({'message': 'Processed'})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

