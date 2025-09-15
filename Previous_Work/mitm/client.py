import socket

HOST = 'localhost'  # Normally: google.com, but DNS will redirect
PORT = 8082         # Flask portal

request = (
    "GET / HTTP/1.1\r\n"
    "Host: google.com\r\n"
    "User-Agent: victim-browser\r\n"
    "Connection: close\r\n"
    "\r\n"
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((HOST, PORT))
    sock.sendall(request.encode())

    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

print(f"[VICTIM] Response:\n{response.decode(errors='ignore')}")

