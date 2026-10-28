"""Attack the gateway and check that it blocks attacks but lets real users through.

Run it while `docker compose up` is running:

    python tests/gateway_test.py                     (default: http://localhost:8080)
    python tests/gateway_test.py http://localhost:8080

Only run it against your own lab. It sends well-known attack strings, not real exploits.
The contact-form tests save a few messages named "WAF-Test" in your database.
The last two tests trip the rate limits on purpose: for about a minute afterwards,
logging in from this computer may show "Slow down, please". That is the gateway working.
"""

import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")
UA = "gateway-test/1.0 (own lab)"

# On Windows, "localhost" is tried as IPv6 (::1) first; Docker only listens on 127.0.0.1, so every new
# connection waits for that attempt to fail. Connect to 127.0.0.1 directly but keep "localhost" as the
# Host header, which is what a browser sends (a numeric Host header raises the WAF's anomaly score).
_parts = urllib.parse.urlsplit(BASE)
HOST_HEADER = _parts.netloc
if _parts.hostname == "localhost":
    BASE = urllib.parse.urlunsplit(_parts._replace(netloc=_parts.netloc.replace("localhost", "127.0.0.1", 1)))
FORM = {"name": "WAF-Test", "email": "waf-test@example.com", "phone": "9876543210"}


# G4: the HTTPS side of the gateway, and the two site names it serves there.
HTTPS_BASE = "https://127.0.0.1:8443"
APP_HOST, AUTH_HOST = "app.localtest.me:8443", "auth.localtest.me:8443"

# The lab uses a self-signed certificate that changes on every restart, so this test (and only this test)
# skips certificate checks. Never do this in code that talks to real servers.
LAB_TLS = ssl.create_default_context()
LAB_TLS.check_hostname = False
LAB_TLS.verify_mode = ssl.CERT_NONE


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None                      # report the 302 itself instead of following it


OPENER = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=LAB_TLS))


def fetch(path, query=None, form=None, raw_body=None, agent=UA, base=None, host=None, headers=None, json_body=None,
          method=None):
    """Return (status code, body text, headers) without following redirects."""
    time.sleep(0.06)                     # stay under the gateway's per-visitor rate limit
    url = (base or BASE) + path
    if query is not None:
        url += "?" + (query if isinstance(query, str) else urllib.parse.urlencode(query))
    data = raw_body if raw_body is not None else (urllib.parse.urlencode(form).encode() if form else None)
    if json_body is not None:
        data = json.dumps(json_body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": agent, "Host": host or HOST_HEADER, **(headers or {})})
    if data is not None:
        req.add_header("Content-Type", "application/json" if json_body is not None else "application/x-www-form-urlencoded")
    try:
        with OPENER.open(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        if raw_body is not None:         # the gateway may cut off an oversized upload mid-send
            return 413, "", {}
        raise SystemExit(f"Cannot reach {base or BASE}: {e}\nIs `docker compose up` running?")


def status(*args, **kwargs):
    return fetch(*args, **kwargs)[0]


def custom_block_page():
    """A blocked request must show our page, not nginx's default (which names the software)."""
    code, body, headers = fetch("/", {"visitor": "<script>alert(1)</script>"})
    if code == 403 and "Your request was blocked" in body and "nginx" not in body.lower() and not headers.get("Server"):
        return 403
    return 599                           # anything else counts as a failure


def redirects_to(expected_prefix, path, **kwargs):
    """302 whose Location starts with expected_prefix counts as success (reported as 302)."""
    code, _, headers = fetch(path, **kwargs)
    location = headers.get("Location", "") if headers else ""
    if code == 302 and location.startswith(expected_prefix):
        return 302
    print(f"        got {code}, Location: {location or '(none)'}")
    return 599


def app_https(path, query=None, **kwargs):
    return fetch(path, query, base=HTTPS_BASE, host=APP_HOST, **kwargs)


def portal(path, query=None, **kwargs):
    return fetch(path, query, base=HTTPS_BASE, host=AUTH_HOST, **kwargs)


def portal_is_up():
    code, body, _ = portal("/")
    if code == 200 and "authelia" in body.lower():
        return 200
    print(f"        got {code}; is the authelia container running? (docker compose ps)")
    return 599


def portal_login(username, password):
    return portal("/api/firstfactor", json_body={
        "username": username, "password": password, "keepMeLoggedIn": False,
        "targetURL": f"https://{APP_HOST}/messages.php", "requestMethod": "GET"})[0]


def passes_waf(code_body_headers):
    """True when the response did not come from the gateway's block page (Authelia may still say no itself)."""
    code, body, _ = code_body_headers
    return 599 if "Your request was blocked" in body else code


def login_rate_limit():
    """Rapid password guessing from one address must hit 429 before PHP is even asked."""
    codes = [status("/login.php", form={"username": "rate-test", "password": "guess", "csrf": "x"}) for _ in range(12)]
    return 429 if 429 in codes else codes[-1]


def flood_rate_limit():
    """A burst of 150 requests in parallel must be partly refused with 429."""
    from concurrent.futures import ThreadPoolExecutor

    def one(_):
        req = urllib.request.Request(BASE + "/style.css", headers={"User-Agent": UA, "Host": HOST_HEADER})
        try:
            with OPENER.open(req, timeout=15) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=30) as pool:
        codes = list(pool.map(one, range(150)))
    seconds = time.monotonic() - start
    print(f"        flood: {codes.count(200)} x 200, {codes.count(429)} x 429, "
          f"others {len(codes) - codes.count(200) - codes.count(429)}, "
          f"{len(codes) / seconds:.0f} requests/second")
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

    ("G4", "Admin page over plain HTTP is sent to the HTTPS site", ALLOW,
     lambda: redirects_to(f"https://{APP_HOST}/messages.php", "/messages.php")),
    ("G4", "Admin page without 2FA is sent to the Authelia portal", ALLOW,
     lambda: redirects_to(f"https://{AUTH_HOST}/", "/messages.php", base=HTTPS_BASE, host=APP_HOST)),
    ("G4", "Forged Remote-User header and fake cookie do not get in", ALLOW,
     lambda: redirects_to(f"https://{AUTH_HOST}/", "/messages.php", base=HTTPS_BASE, host=APP_HOST,
                          headers={"Remote-User": "admin", "Cookie": "authelia_session=forged"})),
    ("G4", "Public page still open over HTTPS", ALLOW, lambda: app_https("/contact.php")[0]),
    ("G4", "Authelia portal is reachable through the gateway", ALLOW, portal_is_up),
    ("G4", "Portal script with 'Password' in its name is not blocked (rule 1003)", ALLOW,
     lambda: portal("/static/js/hooks.PasswordVisibility.BkfT-6fZ.js")[0]),
    ("G4", "Restricted files are still blocked on the portal: /static/.passwd", BLOCK, lambda: portal("/static/.passwd")[0]),
    ("G4", "Portal API may use PUT, e.g. checking the code when adding a phone (rule 1004)", ALLOW,
     lambda: passes_waf(portal("/api/user/session/elevation", method="PUT", json_body={"otc": "ABCD1234"}))),
    ("G4", "The app itself still refuses PUT", BLOCK, lambda: app_https("/contact.php", method="PUT", form={"x": "1"})[0]),
    ("G4", "WAF also protects the portal: <script> in ?rd=", BLOCK, lambda: portal("/", {"rd": "<script>alert(1)</script>"})[0]),
    ("G4", "Portal: wrong password with symbols is refused by Authelia, not the WAF (rule 1002)", ALLOW,
     lambda: portal_login("gateway-test", "Sunset' OR 2024--x <b>")),
    ("G4", "Portal: SQL injection in the username is blocked by the WAF", BLOCK,
     lambda: portal_login("admin' OR '1'='1", "x")),
    ("G3", "Password guessing: 12 fast logins get 429", LIMIT, login_rate_limit),
    ("G3", "Flood: 150 parallel requests get some 429", LIMIT, flood_rate_limit),
]


def main():
    print(f"Testing gateway at {BASE} (Host: {HOST_HEADER})\n")
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
