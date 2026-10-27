"""Attack the gateway and check that it blocks attacks but lets real users through.

Run it while `docker compose up` is running:

    python tests/gateway_test.py                     (default: http://localhost:8080)
    python tests/gateway_test.py http://localhost:8080

Only run it against your own lab. It sends well-known attack strings, not real exploits.
The contact-form tests save a few messages named "WAF-Test" in your database.
The last two tests trip the rate limits on purpose: for about a minute afterwards,
logging in from this computer may show "Slow down, please". That is the gateway working.
"""

import sys
import time
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


def fetch(path, query=None, form=None, raw_body=None, agent=UA):
    """Return (status code, body text, headers) without following redirects."""
    time.sleep(0.06)                     # stay under the gateway's per-visitor rate limit
    url = BASE + path
    if query is not None:
        url += "?" + (query if isinstance(query, str) else urllib.parse.urlencode(query))
    data = raw_body if raw_body is not None else (urllib.parse.urlencode(form).encode() if form else None)
    req = urllib.request.Request(url, data=data, headers={"User-Agent": agent})
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with OPENER.open(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        if raw_body is not None:         # the gateway may cut off an oversized upload mid-send
            return 413, "", {}
        raise SystemExit(f"Cannot reach {BASE}: {e}\nIs `docker compose up` running?")


def status(*args, **kwargs):
    return fetch(*args, **kwargs)[0]


def custom_block_page():
    """A blocked request must show our page, not nginx's default (which names the software)."""
    code, body, headers = fetch("/", {"visitor": "<script>alert(1)</script>"})
    if code == 403 and "Your request was blocked" in body and "nginx" not in body.lower() and not headers.get("Server"):
        return 403
    return 599                           # anything else counts as a failure


def login_rate_limit():
    """Rapid password guessing from one address must hit 429 before PHP is even asked."""
    codes = [status("/login.php", form={"username": "rate-test", "password": "guess", "csrf": "x"}) for _ in range(12)]
    return 429 if 429 in codes else codes[-1]


def flood_rate_limit():
    """A burst of 150 requests in parallel must be partly refused with 429."""
    from concurrent.futures import ThreadPoolExecutor

    def one(_):
        req = urllib.request.Request(BASE + "/style.css", headers={"User-Agent": UA})
        try:
            with OPENER.open(req, timeout=15) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=30) as pool:
        codes = list(pool.map(one, range(150)))
    time.sleep(3)                        # let the bucket refill
    return 429 if 429 in codes and 200 in codes else 599


def message(text):
    return {**FORM, "message": text}


BLOCK, ALLOW, LIMIT = "blocked", "allowed", "rate-limited"
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

    ("G3", "Blocked visitors see our own page (no 'nginx', no Server header)", BLOCK, custom_block_page),
    ("G3", "Webshell: /uploads/shell.php?cmd=id", BLOCK, lambda: status("/uploads/shell.php", {"cmd": "id"})),
    ("G3", "Webshell: /images/avatar.phtml", BLOCK, lambda: status("/images/avatar.phtml")),
    ("G3", "Error pages cannot be opened directly", ALLOW, lambda: status("/errors/blocked.html")),
    ("G3", "Health check for monitoring: /healthz", ALLOW, lambda: status("/healthz")),
    ("G3", "Password guessing: 12 fast logins get 429", LIMIT, login_rate_limit),
    ("G3", "Flood: 150 parallel requests get some 429", LIMIT, flood_rate_limit),
]


def main():
    print(f"Testing gateway at {BASE}\n")
    failures = 0
    for group, text, expected, run in CASES:
        code = run()
        got = BLOCK if code in (403, 413) else LIMIT if code == 429 else ALLOW
        ok = got == expected and code < 500
        if expected == ALLOW and code == 429 and group == "Tuned":
            ok = True                    # a rate limit left over from an earlier run is not a WAF failure
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {group:<6}  {code}  {text}" + ("" if ok else f"   (expected {expected})"))
    print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
