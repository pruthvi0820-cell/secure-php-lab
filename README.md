# Secure PHP Lab

A small PHP + MySQL web app built step by step to learn how common web attacks work and how to stop
them. Every defence was tested by attacking it locally first.

Built by Pruthvi DR while learning PHP, with AI guidance (Claude).

## What it does

- **Contact form** that validates input and saves messages to MySQL
- **Admin login** (the first account created becomes the admin; registration then closes)
- **Messages page** visible only to the logged-in admin, with search
- **Security gateway** in front of the app: a web application firewall (WAF) that blocks attacks
  before they reach PHP

```
Browser ──► Gateway: nginx + ModSecurity + OWASP Core Rule Set ──► PHP 8.4 ──► MySQL 8.4
            (the only open port)                                    (hidden)    (hidden)
```

## Security features

| Attack | Defence in this app | Where |
|---|---|---|
| Cross-site scripting (XSS) | Every output escaped with `htmlspecialchars()`; Content-Security-Policy header | `src/bootstrap.php` |
| SQL injection | Prepared statements only (`prepare` + `execute`), never string-built SQL | all pages |
| Password theft from a leaked database | `password_hash()` (bcrypt, cost 12) and `password_verify()` | `register.php`, `login.php` |
| Brute-force password guessing | 5 failures per username / 20 per IP in 15 minutes, then locked | `src/auth.php` |
| Username discovery | Same error and same response time for wrong username and wrong password | `login.php` |
| Cross-site request forgery (CSRF) | Random token in every POST form, checked with `hash_equals()`; SameSite cookie | `src/auth.php` |
| Session hijacking / fixation | HttpOnly cookie, strict session mode, new session ID on login, 15-minute idle timeout | `src/auth.php` |
| Clickjacking | `X-Frame-Options: DENY` and `frame-ancestors 'none'` | `src/bootstrap.php` |
| Information leaks | Generic error messages (details only in server logs), no PHP/Apache version in headers, production `php.ini` | `compose.yaml` |
| Secrets in source code | Passwords in `.env` (ignored by Git), code outside the web root | `.env.example`, `src/` |
| Malformed input (arrays instead of text) | `post_string()` treats anything that is not text as empty | `src/auth.php` |
| Attacks reaching the app at all | WAF (OWASP CRS 4.30, paranoia level 1) blocks SQLi, XSS, traversal, PHP/command injection, scanners and bodies over 2 MB with a 403 | `compose.yaml` |
| Direct access to PHP or MySQL | Only the gateway publishes a port; PHP and MySQL sit on Docker's private network | `compose.yaml` |
| Spoofed visitor IP | Apache `mod_remoteip` trusts `X-Real-IP` only from Docker's private network, so brute-force limits use the real IP | `compose.yaml` |

## Run it

Requires Docker Desktop.

```bash
cp .env.example .env        # Windows: copy .env.example .env
# edit .env and set long random passwords
docker compose up --build
```

Open http://localhost:8080/register.php to create the admin account, then
http://localhost:8080/contact.php and http://localhost:8080/messages.php.

The app listens on `127.0.0.1` only, so it is not reachable from other devices on the network.

## Security gateway (WAF)

The gateway is the official `owasp/modsecurity-crs` image (nginx + ModSecurity v3 + OWASP Core Rule Set).
Each request gets an anomaly score from about 850 rules; at 5 or more it is refused with **403** and PHP
never sees it.

**Tuning false positives.** At first the WAF also blocked real users: a recruiter writing
*"Saw your post about blocking ' OR '1'='1 attacks"*, and a strong password containing `' OR`.
Instead of switching rules off globally, [`gateway/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`](gateway/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf)
makes two narrow exceptions, each with the reason it is safe:

| Rule | Exception | Why it is safe |
|---|---|---|
| 1000 | Do not inspect `password` / `confirm` on `login.php` and `register.php` | Passwords are only ever hashed, never put into SQL or HTML |
| 1001 | Skip SQLi, XSS and file-path checks on the `message` field of `contact.php` only | The app stores it with a prepared statement and prints it with `htmlspecialchars()` |

Command-injection and PHP-injection checks stay on for every field. A message containing
`; cat /etc/passwd` is still blocked: an accepted trade-off.

**Automated attack test.** With the stack running:

```bash
python tests/gateway_test.py
```

It sends 26 requests (15 attacks, 7 normal visits, 4 tuning cases) and prints PASS/FAIL for each.
Behind the gateway all 26 pass; pointed straight at PHP without the WAF, only 10 do.
Reading why a request was blocked: `docker compose logs proxy --tail 5` (look for `ruleId` and `message`).

## Project layout

```
public/      web root: only these files can be opened in a browser
  index.php, contact.php, login.php, logout.php, register.php, messages.php, style.css
src/         code that is never served directly
  bootstrap.php   loads helpers and sends security headers on every page
  auth.php        sessions, CSRF tokens, brute-force limits
  db.php          database connection (settings from environment variables)
gateway/     WAF tuning rules (REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf)
tests/       gateway_test.py: automated attack and false-positive test
init.sql, users.sql   database tables (loaded automatically on first start)
compose.yaml          WAF gateway, PHP 8.4 + Apache, MySQL 8.4
```

## Manual security tests

| Test | Expected |
|---|---|
| Open `/messages.php` without logging in | Redirected to the login page |
| Search messages for `' OR '1'='1` | 0 results (SQL injection blocked) |
| Send the contact form with name `<script>alert(1)</script>` | Shown as plain text, no popup |
| Enter a wrong password 6 times | "Too many failed attempts" |
| Log in with a username that does not exist | Same message as a wrong password |
| Open `/register.php` after the admin exists | "Registration is closed" |
| Browser console: `document.cookie` while logged in | Session cookie not visible (HttpOnly) |
| Open `/logout.php` directly | 405: logout needs the button (POST + CSRF token) |

## Not production-ready (yet)

This is a learning project. A real deployment would also need HTTPS (and the cookie `secure` flag),
rate limiting at the gateway, two-factor login, email verification and password reset, and unit tests.
The next steps of this project add rate limiting, a zero-trust login (Authelia with 2FA) and HTTPS.
