"""Small flask app with deliberate bugs, used as a test target for ProofScan.

Runs on 127.0.0.1 only. Never put this on a network.

Some endpoints are safe but look vulnerable (/plain, /jitter). Those are the
false positives the scanner has to reject. ANSWER_KEY below is the ground truth
I check the results against.

    python labs/vulnerable_app/app.py     ->  http://127.0.0.1:5001
"""
import html
import random
import sqlite3
import time

from flask import Flask, Response, request

app = Flask(__name__)

ANSWER_KEY = {
    "/product":      {"sqli": True,  "xss": False},   # id goes straight into the query
    "/safe-product": {"sqli": False, "xss": False},   # parameterised
    "/login":        {"sqli": True,  "xss": False},
    "/search":       {"sqli": False, "xss": True},    # reflected, not escaped
    "/safe-search":  {"sqli": False, "xss": False},
    "/comment":      {"sqli": False, "xss": True},    # inside an attribute
    "/plain":        {"sqli": False, "xss": False},   # reflected but never runs
    "/jitter":       {"sqli": False, "xss": False},   # just slow sometimes
}

PRODUCTS = [
    (1, "Laptop", 45000), (2, "Keyboard", 1200),
    (3, "Monitor", 9500), (4, "Mouse", 600),
]
USERS = [(1, "admin", "s3cr3t"), (2, "abul", "hunter2")]


def db():
    # fresh db per request, the tables are tiny so this is fine
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE products (id INT, name TEXT, price INT)")
    conn.executemany("INSERT INTO products VALUES (?,?,?)", PRODUCTS)
    conn.execute("CREATE TABLE users (id INT, username TEXT, password TEXT)")
    conn.executemany("INSERT INTO users VALUES (?,?,?)", USERS)
    return conn


def page(title, body):
    return f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"


@app.route("/")
def home():
    return page("ProofScan test target", """
        <h1>ProofScan test target</h1>
        <p>Deliberately weak app, local testing only.</p>
        <ul>
          <li><a href="/product?id=1">Product lookup (weak)</a></li>
          <li><a href="/safe-product?id=1">Product lookup (safe)</a></li>
          <li><a href="/search?q=hello">Search (weak)</a></li>
          <li><a href="/safe-search?q=hello">Search (safe)</a></li>
          <li><a href="/comment?q=hello">Comment box (weak)</a></li>
          <li><a href="/plain?q=hello">Plain text echo (safe)</a></li>
          <li><a href="/jitter?id=1">Slow endpoint (safe)</a></li>
          <li><a href="/login">Login form (weak)</a></li>
        </ul>""")


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    query = f"SELECT name, price FROM products WHERE id = {pid}"    # injectable
    try:
        rows = db().execute(query).fetchall()
    except Exception as e:
        return page("Error", f"<h1>Database error</h1><pre>{e}</pre>"), 500
    if not rows:
        return page("Product", "<h1>No product found</h1>")
    items = "".join(f"<li>{n} - Rs {p}</li>" for n, p in rows)
    return page("Product", f"<h1>Product</h1><ul>{items}</ul>")


@app.route("/safe-product")
def safe_product():
    pid = request.args.get("id", "1")
    rows = db().execute("SELECT name, price FROM products WHERE id = ?", (pid,)).fetchall()
    if not rows:
        return page("Product", "<h1>No product found</h1>")
    items = "".join(f"<li>{n} - Rs {p}</li>" for n, p in rows)
    return page("Product", f"<h1>Product</h1><ul>{items}</ul>")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = ('<form method="post">'
            '<input name="username" placeholder="username">'
            '<input name="password" type="password" placeholder="password">'
            '<input type="submit" value="Log in"></form>')
    if request.method == "GET":
        return page("Login", f"<h1>Login</h1>{form}")

    user = request.form.get("username", "")
    pwd = request.form.get("password", "")
    query = (f"SELECT username FROM users "
             f"WHERE username = '{user}' AND password = '{pwd}'")     # injectable
    try:
        rows = db().execute(query).fetchall()
    except Exception as e:
        return page("Login", f"<h1>Database error</h1><pre>{e}</pre>{form}"), 500
    if rows:
        return page("Login", f"<h1>Welcome {html.escape(rows[0][0])}</h1>")
    return page("Login", f"<h1>Invalid credentials</h1>{form}")


@app.route("/search")
def search():
    q = request.args.get("q", "")                                     # not escaped
    return page("Search", f"<h1>Results for: {q}</h1><p>Nothing found.</p>")


@app.route("/safe-search")
def safe_search():
    q = html.escape(request.args.get("q", ""))
    return page("Search", f"<h1>Results for: {q}</h1><p>Nothing found.</p>")


@app.route("/comment")
def comment():
    q = request.args.get("q", "")
    return page("Comment", f'<h1>Your comment</h1><div title="{q}">saved</div>')


@app.route("/plain")
def plain():
    # reflects the input word for word, but as plain text so it never runs.
    # a scanner that only checks "did my payload come back" flags this.
    q = request.args.get("q", "")
    return Response(f"You searched for: {q}", mimetype="text/plain")


@app.route("/jitter")
def jitter():
    # about 1 in 6 requests is slow. a timing check that trusts one slow
    # response will report a bug here. one that takes several samples will not.
    if random.random() < 0.17:
        time.sleep(1.0)
    return page("Jitter", f"<h1>id = {html.escape(request.args.get('id', '1'))}</h1>")


if __name__ == "__main__":
    print("test target -> http://127.0.0.1:5001  (local only)")
    app.run(host="127.0.0.1", port=5001, debug=False)
