from flask import Flask, render_template, request, redirect
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

app = Flask(__name__)


# ---------- AES FUNCTIONS ----------
def generate_key(password):
    return hashlib.sha256(password.encode()).digest()[:16]

def encrypt_AES(text, password):
    key = generate_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(text.encode(), AES.block_size))

def decrypt_AES(enc_text, password):
    key = generate_key(password)
    iv = enc_text[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc_text[16:]), AES.block_size).decode()


# ---------- ROUTES ----------
@app.route("/")
def home():
    return render_template("index.html")


# -------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not os.path.exists("users.txt"):
            return "No users registered yet!"

        with open("users.txt", "r") as f:
            users = dict(line.strip().split(":") for line in f.readlines())

        if username in users and users[username] == password:
            return redirect(f"/write?username={username}&password={password}")
        else:
            return "Wrong username or password!"

    return render_template("login.html",
                           error="wrong username or password!")


# -------- SIGNUP ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        users = {}
        if os.path.exists("users.txt"):
            with open("users.txt", "r") as f:
                users = dict(line.strip().split(":") for line in f.readlines())

        if username in users:
            return "Username already exists!"

        with open("users.txt", "a") as f:
            f.write(f"{username}:{password}\n")

        return redirect("/login")

    return render_template("signup.html")


# -------- WRITE ENTRY ----------
@app.route("/write", methods=["GET", "POST"])
def write_entry():
    username = request.args.get("username")
    password = request.args.get("password")

    if request.method == "POST":
        entry = request.form["entry"]
        enc = encrypt_AES(entry, password)

        with open(f"{username}_diary.txt", "ab") as f:
            f.write(enc + b"\n")

        return "Entry Saved Successfully!"

    return render_template("diary.html", username=username, password=password)


# -------- READ ENTRY ----------
@app.route("/read")
def read_entries():
    username = request.args.get("username")
    password = request.args.get("password")

    entries = []
    try:
        with open(f"{username}_diary.txt", "rb") as f:
            for line in f:
                dec = decrypt_AES(line.strip(), password)
                entries.append(dec)
    except:
        return "No entries or wrong password!"

    return render_template("read.html", 
                           entries=entries, 
                           username=username, 
                           password=password)


# -------- DELETE ENTRY ----------
@app.route("/delete")
def delete_entries():
    username = request.args.get("username")

    try:
        os.remove(f"{username}_diary.txt")
        return "Diary deleted!"
    except:
        return "No diary found!"


# Run App
if __name__ == "__main__":    # <- FIXED HERE
    print("Starting Flask app…")
    app.run(debug=True)