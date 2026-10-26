"""Attack the gateway and check that it blocks attacks but lets real users through.

Run it while `docker compose up` is running:

    python tests/gateway_test.py                     (default: http://localhost:8080)
    python tests/gateway_test.py http://localhost:8080

Only run it against your own lab. It sends well-known attack strings, not real exploits.
The contact-form tests save a few messages named "WAF-Test" in your database.
"""

import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")
UA = "gateway-test/1.0 (own lab)"
FORM = {"name": "WAF-Test", "email": "waf-test@example.com", "phone": "9876543210"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None                      # report the 302 itself instead of following it


OPENER = urllib.request.build_opener(NoRedirect)


def status(path, query=None, form=None, raw_body=None, agent=UA):
    url = BASE + path
    if query is not None:
        url += "?" + (query if isinstance(query, str) else urllib.parse.urlencode(query))
    data = raw_body if raw_body is not None else (urllib.parse.urlencode(form).encode() if form else None)
    req = urllib.request.Request(url, data=data, headers={"User-Agent": agent})
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with OPENER.open(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        if raw_body is not None:         # the gateway may cut off an oversized upload mid-send
            return 413
        raise SystemExit(f"Cannot reach {BASE}: {e}\nIs `docker compose up` running?")


def message(text):
    return {**FORM, "message": text}


BLOCK, ALLOW = "blocked", "allowed"
CASES = [
    # (group, description, expected, request)
    ("Attack", "XSS: <script> in a URL parameter", BLOCK, lambda: status("/", {"visitor": "<script>alert(1)</script>"})),
    ("Attack", "XSS: <img onerror> in a URL parameter", BLOCK, lambda: status("/", {"visitor": "<img src=x onerror=alert(1)>"})),
    ("Attack", "SQL injection: ' OR '1'='1 in search", BLOCK, lambda: status("/messages.php", {"q": "' OR '1'='1"})),
    ("Attack", "SQL injection: UNION SELECT password_hash", BLOCK,
     lambda: status("/messages.php", {"q": "x' UNION SELECT username,password_hash FROM users-- -"})),
    ("Attack", "Path traversal: ../../etc/passwd", BLOCK, lambda: status("/", {"file": "../../../../etc/passwd"})),
    ("Attack", "PHP wrapper: php://filter", BLOCK,
     lambda: status("/", {"page": "php://filter/convert.base64-encode/resource=index.php"})),
    ("Attack", "Command injection: ; cat /etc/passwd", BLOCK, lambda: status("/messages.php", {"q": "x; cat /etc/passwd"})),
    ("Attack", "PHP-CGI argument injection: ?-d allow_url_include", BLOCK, lambda: status("/index.php", "-d+allow_url_include%3d1")),
    ("Attack", "Secret file: /.env", BLOCK, lambda: status("/.env")),
    ("Attack", "Source code: /.git/HEAD", BLOCK, lambda: status("/.git/HEAD")),
    ("Attack", "Hacking tool: sqlmap user-agent", BLOCK, lambda: status("/login.php", agent="sqlmap/1.8")),
    ("Attack", "XSS in contact form NAME field", BLOCK,
     lambda: status("/contact.php", form={**message("hello there friend"), "name": "<script>alert(1)</script>"})),
    ("Attack", "SQL injection in contact form EMAIL field", BLOCK,
     lambda: status("/contact.php", form={**message("hello there friend"), "email": "x' OR '1'='1"})),
    ("Attack", "PHP code in contact MESSAGE field", BLOCK, lambda: status("/contact.php", form=message('<?php system($_GET["c"]); ?>'))),
    ("Attack", "Upload over 2 MB", BLOCK, lambda: status("/contact.php", raw_body=b"a" * 3_000_000)),

    ("Normal", "Home page", ALLOW, lambda: status("/")),
    ("Normal", "Home page with ?visitor=Recruiter", ALLOW, lambda: status("/", {"visitor": "Recruiter"})),
    ("Normal", "Login page", ALLOW, lambda: status("/login.php")),
    ("Normal", "Stylesheet", ALLOW, lambda: status("/style.css")),
    ("Normal", "Contact: ordinary message", ALLOW,
     lambda: status("/contact.php", form=message("Hi Pruthvi, loved your ATS project. Can we talk on Monday?"))),
    ("Normal", "Contact: name with apostrophe (O'Brien)", ALLOW,
     lambda: status("/contact.php", form={**message("Hello, I'd like to connect about a role."), "name": "Sean O'Brien"})),
    ("Normal", "Contact: message with <3 & 100%", ALLOW, lambda: status("/contact.php", form=message("Great work <3 & keep going! 100% impressed :)"))),

    ("Tuned", "Recruiter writes about ' OR '1'='1 (exclusion 1001)", ALLOW,
     lambda: status("/contact.php", form=message("Saw your post about blocking ' OR '1'='1 attacks with prepared statements. Impressive!"))),
    ("Tuned", "Recruiter writes about <script> tags (exclusion 1001)", ALLOW,
     lambda: status("/contact.php", form=message("Loved how you stopped <script> tags with htmlspecialchars. Let's talk."))),
    ("Tuned", "Password containing ' OR (exclusion 1000)", ALLOW,
     lambda: status("/login.php", form={"username": "admin", "password": "Sunset' OR 2024--x", "csrf": "x"})),
    ("Tuned", "Message with ; cat /etc/passwd stays blocked (on purpose)", BLOCK,
     lambda: status("/contact.php", form=message("Your traversal demo; cat /etc/passwd was clever."))),
]


def main():
    print(f"Testing gateway at {BASE}\n")
    failures = 0
    for group, text, expected, run in CASES:
        code = run()
        got = BLOCK if code in (403, 413) else ALLOW
        ok = got == expected and code < 500
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {group:<6}  {code}  {text}" + ("" if ok else f"   (expected {expected})"))
    print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
