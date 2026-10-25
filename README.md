# Secure PHP Lab

A small PHP + MySQL web app built step by step to learn how common web attacks work and how to stop
them. Every defence was tested by attacking it locally first.

Built by Pruthvi DR while learning PHP, with AI guidance (Claude).

## What it does

- **Contact form** that validates input and saves messages to MySQL
- **Admin login** (the first account created becomes the admin; registration then closes)
- **Messages page** visible only to the logged-in admin, with search

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

## Project layout

```
public/      web root: only these files can be opened in a browser
  index.php, contact.php, login.php, logout.php, register.php, messages.php, style.css
src/         code that is never served directly
  bootstrap.php   loads helpers and sends security headers on every page
  auth.php        sessions, CSRF tokens, brute-force limits
  db.php          database connection (settings from environment variables)
init.sql, users.sql   database tables (loaded automatically on first start)
compose.yaml          PHP 8.4 + Apache and MySQL 8.4
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
a proper rate limiter behind a reverse proxy, email verification and password reset, and automated tests.
