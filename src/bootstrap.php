<?php
// Every page starts with: require __DIR__ . "/../src/bootstrap.php";
// It must be the FIRST line, before any HTML, because headers can only be sent before output.
require __DIR__ . "/db.php";
require __DIR__ . "/auth.php";

function e($text): string {
    return htmlspecialchars((string) $text, ENT_QUOTES, "UTF-8");
}

function send_security_headers(): void {
    header_remove("X-Powered-By");                                    // do not advertise the PHP version
    header("Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; "
         . "form-action 'self'; frame-ancestors 'none'");             // only our own scripts, styles, forms
    header("X-Content-Type-Options: nosniff");                       // browser must trust our content types
    header("X-Frame-Options: DENY");                                 // no hiding our pages inside other sites
    header("Referrer-Policy: no-referrer");                          // do not leak our URLs to other sites
    header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
}

send_security_headers();