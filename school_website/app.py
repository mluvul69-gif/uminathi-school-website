from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import sqlite3
from datetime import datetime
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
# ----------------------
# App setup
# ----------------------
app = Flask(__name__)
app.secret_key = "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

UPLOAD_FOLDER = os.path.join(BASE_DIR, "static/uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# ----------------------
# Admin credentials
# ----------------------
ADMIN_USERNAME = "admin"
SALT = b"uminathi_fixed_salt_2026"

def hash_password(password: str) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

def verify_password(stored_hash: str, password_attempt: str) -> bool:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
        backend=default_backend()
    )
    try:
        kdf.verify(password_attempt.encode(), base64.urlsafe_b64decode(stored_hash))
        return True
    except Exception:
        return False

ADMIN_PASSWORD_HASH = hash_password("2026")

# ----------------------
# Database helpers
# ----------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT NOT NULL,
            image TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ----------------------
# Utility helpers
# ----------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ----------------------
# Public routes
# ----------------------
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/history")
def history():
    return render_template("history.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

def fetch_posts_by_category(category):
    conn = get_db()
    posts = conn.execute(
        "SELECT * FROM posts WHERE category = ? ORDER BY id DESC",
        (category,)
    ).fetchall()
    conn.close()
    return posts

@app.route("/sports")
def sports():
    posts = fetch_posts_by_category("Sports")
    return render_template(
        "sports.html",
        page_title="Sports",
        page_subtitle="Latest sports updates and match highlights.",
        posts=posts,
        current_year=datetime.now().year
    )

@app.route("/reports")
def report():
    posts = fetch_posts_by_category("Reports")
    return render_template(
        "reports.html",
        page_title="Reports",
        page_subtitle="Our latest reports at uMinathi Christian-College.",
        posts=posts,
        current_year=datetime.now().year
    )

@app.route("/news")
def news():
    posts = fetch_posts_by_category("News")
    return render_template(
        "news.html",
        page_title="News",
        page_subtitle="Official announcements and important updates from the school.",
        posts=posts,
        current_year=datetime.now().year
    )

@app.route("/culture")
def culture():
    posts = fetch_posts_by_category("Culture")
    return render_template(
        "culture.html",
        page_title="Culture",
        page_subtitle="Celebrating tradition, values, and student life",
        posts=posts,
        current_year=datetime.now().year
    )

@app.route("/academics")
def academics():
    posts = fetch_posts_by_category("Academics")
    return render_template(
        "academics.html",
        page_title="Academics",
        page_subtitle="Celebrating tradition, values, and student life",
        posts=posts,
        current_year=datetime.now().year
    )

# ----------------------
# Admin authentication
# ----------------------
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and verify_password(ADMIN_PASSWORD_HASH, password):
            session["admin_logged_in"] = True
            return redirect(url_for("admin"))
        flash("Invalid credentials", "danger")

    return render_template("admin_login.html")

@app.route("/admin-logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

# ----------------------
# Admin panel
# ----------------------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    conn = get_db()

    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        category = request.form.get("category")
        file = request.files.get("image")

        if not title or not content or not category:
            flash("Title, content and category are required", "danger")
            return redirect(url_for("admin"))

        filename = None

        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Invalid image type", "danger")
                return redirect(url_for("admin"))

            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        conn.execute("""
            INSERT INTO posts (title, content, category, image, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            title,
            content,
            category,
            filename,
            datetime.now().strftime("%b %d, %Y")
        ))

        conn.commit()
        flash("Post published", "success")

    posts = conn.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    conn.close()

    return render_template("admin.html", posts=posts)

# ----------------------
# Delete post
# ----------------------
@app.route("/admin/delete/<int:post_id>", methods=["POST"])
def delete_post(post_id):
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    conn = get_db()
    post = conn.execute("SELECT image FROM posts WHERE id = ?", (post_id,)).fetchone()

    if post and post["image"]:
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], post["image"])
        if os.path.exists(image_path):
            os.remove(image_path)

    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("admin"))

# ----------------------
# Run
# ----------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

