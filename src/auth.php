<?php
// Login helpers: sessions, CSRF protection and brute-force limits.
const SESSION_IDLE_SECONDS = 900;      // log out after 15 minutes of no activity
const MAX_FAILS_PER_USER   = 5;        // per username, per 15 minutes
const MAX_FAILS_PER_IP     = 20;       // per IP address, per 15 minutes
const PASSWORD_COST        = 12;
// Checked when the username does not exist, so a wrong username takes as long as a wrong password.
const DUMMY_HASH = '$2y$12$df0E4Oef42oK6lQnWPeDL.A6a8a976X7c2FaQrq3zDxOBKFgPeE12';

function start_session(): void {
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    ini_set("session.use_strict_mode", "1");       // refuse session IDs the server did not create
    session_name("LABSESSID");
    session_set_cookie_params([
        "lifetime" => 0,          // cookie dies when the browser closes
        "path"     => "/",
        "secure"   => false,      // set to true on a real HTTPS site
        "httponly" => true,       // JavaScript cannot read the cookie (limits XSS damage)
        "samesite" => "Lax",      // other sites cannot send it with their forms
    ]);
    session_start();
    if (isset($_SESSION["last_seen"]) && time() - $_SESSION["last_seen"] > SESSION_IDLE_SECONDS) {
        $_SESSION = [];
        session_regenerate_id(true);
    }
    $_SESSION["last_seen"] = time();
}

function current_user(): ?array {
    return $_SESSION["user"] ?? null;
}

function require_login(): array {
    start_session();
    $user = current_user();
    if ($user === null) {
        header("Location: login.php");
        exit;
    }
    return $user;
}

function log_in(array $user): void {
    session_regenerate_id(true);                   // new ID after login stops session fixation
    unset($_SESSION["csrf"]);
    $_SESSION["user"] = ["id" => (int) $user["id"], "username" => $user["username"]];
}

function log_out(): void {
    $_SESSION = [];
    $p = session_get_cookie_params();
    setcookie(session_name(), "", [
        "expires" => time() - 3600, "path" => $p["path"],
        "secure" => $p["secure"], "httponly" => $p["httponly"], "samesite" => $p["samesite"],
    ]);
    session_destroy();
}

function csrf_token(): string {
    if (empty($_SESSION["csrf"])) {
        $_SESSION["csrf"] = bin2hex(random_bytes(32));
    }
    return $_SESSION["csrf"];
}

function check_csrf(): void {
    $sent = $_POST["csrf"] ?? "";
    if (!is_string($sent) || !hash_equals(csrf_token(), $sent)) {
        http_response_code(400);
        exit("Invalid or expired form. Go back, refresh the page and try again.");
    }
}

// Attackers can send arrays (name[]=x) instead of text; treat anything that is not text as empty.
function post_string(string $key): string {
    $value = $_POST[$key] ?? "";
    return is_string($value) ? $value : "";
}

function too_many_failures(string $username, string $ip): bool {
    $byUser = db()->prepare("SELECT COUNT(*) FROM login_attempts
                             WHERE username = ? AND attempted_at > NOW() - INTERVAL 15 MINUTE");
    $byUser->execute([$username]);
    $byIp = db()->prepare("SELECT COUNT(*) FROM login_attempts
                           WHERE ip = ? AND attempted_at > NOW() - INTERVAL 15 MINUTE");
    $byIp->execute([$ip]);
    return (int) $byUser->fetchColumn() >= MAX_FAILS_PER_USER || (int) $byIp->fetchColumn() >= MAX_FAILS_PER_IP;
}

function record_failure(string $username, string $ip): void {
    db()->prepare("INSERT INTO login_attempts (username, ip) VALUES (?, ?)")->execute([$username, $ip]);
}

function clear_failures(string $username): void {
    db()->prepare("DELETE FROM login_attempts WHERE username = ?")->execute([$username]);
}