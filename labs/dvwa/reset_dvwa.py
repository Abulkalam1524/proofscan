"""Create or reset the DVWA database, and set the security level.

Scanning changes DVWA's state. Rows get added, the guestbook fills up, the
sql injection pages start returning different things. A benchmark run has to
start from the same place every time or the numbers mean nothing, so run this
before each one.

    python labs/dvwa/reset_dvwa.py
    python labs/dvwa/reset_dvwa.py --security medium

DVWA guards its own forms with a user_token, so every step here is get the
page, pull the token out, post it back with the cookies from the last response.
That is the same dance ProofScan will have to do to scan anything behind a
login, which is the point of doing it by hand once.
"""
import argparse
import re
import sys

import httpx

BASE = "http://127.0.0.1:8080"
USERNAME = "admin"
PASSWORD = "password"


def token(html):
    """DVWA hides a user_token in every form. Without it the post is dropped."""
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", html)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--security", default="low",
                    choices=["low", "medium", "high", "impossible"])
    args = ap.parse_args()

    with httpx.Client(base_url=args.base, follow_redirects=True, timeout=30) as c:
        setup = c.get("/setup.php")
        if setup.status_code != 200:
            sys.exit(f"setup.php gave {setup.status_code}, is the container up?")

        r = c.post("/setup.php", data={
            "create_db": "Create / Reset Database",
            "user_token": token(setup.text) or "",
        })
        if "Setup successful" not in r.text and "Database has been created" not in r.text:
            # DVWA words this differently between versions, so check it really works
            # rather than trusting the wording
            probe = c.get("/login.php")
            if "user_token" not in probe.text:
                sys.exit("database was not created, setup.php said:\n" + r.text[:800])
        print("database created")

        login_page = c.get("/login.php")
        r = c.post("/login.php", data={
            "username": USERNAME,
            "password": PASSWORD,
            "Login": "Login",
            "user_token": token(login_page.text) or "",
        })
        if "login.php" in str(r.url):
            sys.exit("login failed, still on the login page")
        print(f"logged in as {USERNAME}")

        sec_page = c.get("/security.php")
        c.post("/security.php", data={
            "security": args.security,
            "seclev_submit": "Submit",
            "user_token": token(sec_page.text) or "",
        })
        confirm = c.get("/security.php")
        m = re.search(r"Security Level is currently:?\s*<em>([a-z]+)</em>", confirm.text, re.I)
        print(f"security level: {m.group(1) if m else args.security}")

        print(f"\nready at {args.base}  ({USERNAME}/{PASSWORD})")
        print("session cookie:", dict(c.cookies))


if __name__ == "__main__":
    main()
