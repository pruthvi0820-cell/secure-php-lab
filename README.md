\# Secure PHP Lab



A small PHP + MySQL web app built step by step to learn how common web attacks work and how to stop

them. Every defence was tested by attacking it locally first.



Built by Pruthvi DR while learning PHP, with AI guidance (Claude).



\## What it does



\- \*\*Contact form\*\* that validates input and saves messages to MySQL

\- \*\*Admin login\*\* (the first account created becomes the admin; registration then closes)

\- \*\*Messages page\*\* visible only to the logged-in admin, with search



\## Security features



| Attack | Defence in this app | Where |

|---|---|---|

| Cross-site scripting (XSS) | Every output escaped with `htmlspecialchars()`; Content-Security-Policy header | `src/bootstrap.php` |

| SQL injection | Prepared statements only (`prepare` + `execute`), never string-built SQL | all pages |

| Password theft from a leaked database | `password\_hash()` (bcrypt, cost 12) and `password\_verify()` | `register.php`, `login.php` |

| Brute-force password guessing | 5 failures per username / 20 per IP in 15 minutes, then locked | `src/auth.php` |

| Username discovery | Same error and same response time for wrong username and wrong password | `login.php` |

| Cross-site request forgery (CSRF) | Random token in every POST form, checked with `hash\_equals()`; SameSite cookie | `src/auth.php` |

| Session hijacking / fixation | HttpOnly cookie, strict session mode, new session ID on login, 15-minute idle timeout | `src/auth.php` |

| Clickjacking | `X-Frame-Options: DENY` and `frame-ancestors 'none'` | `src/bootstrap.php` |

| Information leaks | Generic error messages (details only in server logs), no PHP/Apache version in headers, production `php.ini` | `compose.yaml` |

| Secrets in source code | Passwords in `.env` (ignored by Git), code outside the web root | `.env.example`, `src/` |

| Malformed input (arrays instead of text) | `post\_string()` treats anything that is not text as empty | `src/auth.php` |



\## Run it



Requires Docker Desktop.



```bash

cp .env.example .env        # Windows: copy .env.example .env

\# edit .env and set long random passwords

docker compose up --build

