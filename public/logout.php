<?php
require __DIR__ . "/../src/bootstrap.php";

start_session();
// Logout must be a POST with a CSRF token, so another site cannot log you out with a hidden link.
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    exit("Use the Log out button.");
}
check_csrf();
log_out();
header("Location: login.php");
exit;