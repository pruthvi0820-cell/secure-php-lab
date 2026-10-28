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
- **Zero-trust admin area**: the admin pages cannot even be reached without a password and a 6-digit code
  from an authenticator app, checked by Authelia at the gateway, before PHP's own login

```
Browser ──► Security gateway: nginx + ModSecurity WAF + OWASP CRS ──► PHP 8.4 ──► MySQL 8.4
            WAF · rate limits · ban list · block pages                 (hidden)    (hidden)
            admin pages ──► Authelia: password + phone code (hidden)
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
| Floods and password guessing | Gateway rate limits: 20 requests/s per visitor, 10 login attempts/min per visitor, then **429** | `gateway/nginx/` |
| Webshells | A PHP file requested from an upload or media folder is refused at the gateway | `gateway/nginx/location_common.conf.template` |
| Known attackers | Ban list (`deny` lines) checked before anything else; candidates found with PHPGuard | `gateway/deny.conf` |
| Stolen or guessed admin password | Zero-trust gateway login: Authelia requires password + TOTP code (2FA) before any admin page reaches PHP; 3 failures lock the user for 5 minutes | `authelia/configuration.yml` |
| Forged identity headers | The gateway overwrites `Remote-User` on every admin request, so a visitor cannot claim to be someone else | `gateway/nginx/location_common.conf.template` |
| Spoofed visitor IP | Apache `mod_remoteip` trusts `X-Real-IP` only from Docker's private network, so brute-force limits use the real IP | `compose.yaml` |

## Run it

Requires Docker Desktop.

```bash
cp .env.example .env        # Windows: copy .env.example .env
# edit .env and set long random passwords
docker compose up --build
```

Run `python authelia/setup.py` once first (see *Zero-trust admin area*). Then open
https://app.localtest.me:8443/register.php to create the app's admin account (after the gateway login),
and http://localhost:8080/contact.php for the public form.

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

**Warn, slow down, ban (G3).** Blocked visitors get the gateway's own page
([`gateway/errors/blocked.html`](gateway/errors/blocked.html)) instead of nginx's default, which named the
software; it explains what happened and shows the time to quote to the site owner. Visitors who send too
many requests get a *"Slow down, please"* page with status 429. Addresses you decide to ban go in
[`gateway/deny.conf`](gateway/deny.conf) and see the same block page.

**Finding attackers with PHPGuard.** The gateway's access log is in the standard "combined" format, so
[PHPGuard](https://github.com/pruthvi0820-cell/phpguard) can read it:

```bash
docker compose logs proxy --no-log-prefix > logs/gateway.log
python -m phpguard logs logs/gateway.log --canary /db_backup.sql --blocklist logs/block.txt
```

Review `logs/block.txt` by hand before copying an address into `gateway/deny.conf` as `deny <ip>;`.

**Automated attack test.** With the stack running:

```bash
python tests/gateway_test.py
```

It runs 41 checks (15 attacks, 7 normal visits, 4 tuning cases, 7 gateway checks, 8 zero-trust checks:
HTTPS redirect, portal redirect, forged headers, portal WAF) and prints PASS/FAIL for each.
Reading why a request was blocked: `docker compose logs proxy --tail 5` (look for `ruleId` and `message`).

## Zero-trust admin area (G4)

The admin pages (`login.php`, `register.php`, `logout.php`, `messages.php`) are protected **at the gateway**
by [Authelia](https://www.authelia.com) (4.39). For every request to them, nginx asks Authelia
(`auth_request`) whether the visitor has passed **password + one-time code from a phone**; if not, the
visitor is sent to the Authelia portal and PHP never sees the request. After that, PHP's own login still
applies: two independent layers. `messages.php` shows the identity the gateway verified.

| URL | What |
|---|---|
| `http://localhost:8080` | Public pages (admin pages redirect to HTTPS) |
| `https://app.localtest.me:8443` | The app over HTTPS |
| `https://auth.localtest.me:8443` | The Authelia login portal |

`localtest.me` is a public domain whose every name points to `127.0.0.1`, which gives the browser real
domain names for the login cookie without editing the hosts file. The lab certificate is self-signed, so
the browser warns once per site.

Setup, once: `python authelia/setup.py` creates the three secrets and your gateway account (the password
is stored only as an Argon2 hash). Both are in `.gitignore`. Authelia's one-time codes for registering a
phone are written to a file inside its container: `docker compose exec authelia cat /data/notification.txt`.

Decisions worth noting:
- `default_policy: deny`: anything not explicitly listed is refused.
- No "remember me", 5-minute idle timeout, 1-hour maximum session.
- The WAF still inspects the portal; rule 1002 exempts only the JSON `password` field, for the same reason as rule 1000.
- The WAF is switched off only for nginx's internal "ask Authelia" subrequest, whose original request was
  already inspected (CRS rule 920170 otherwise misreads it as a GET with a body).

## Project layout

```
public/      web root: only these files can be opened in a browser
  index.php, contact.php, login.php, logout.php, register.php, messages.php, style.css
src/         code that is never served directly
  bootstrap.php   loads helpers and sends security headers on every page
  auth.php        sessions, CSRF tokens, brute-force limits
  db.php          database connection (settings from environment variables)
gateway/     WAF tuning rules (REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf), nginx rate limits,
             Authelia portal and shared rules (nginx/), ban list (deny.conf), block pages (errors/)
authelia/    configuration.yml, setup.py (creates secrets/ and users_database.yml, both git-ignored)
tests/       gateway_test.py: automated attack and false-positive test
init.sql, users.sql   database tables (loaded automatically on first start)
compose.yaml          WAF gateway, Authelia, PHP 8.4 + Apache, MySQL 8.4
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
a certificate from a real CA, an SMTP server for Authelia's notifications, email verification and
password reset in the app, and unit tests.
