<?php
require __DIR__ . "/../src/bootstrap.php";

start_session();
if (current_user() !== null) {
    header("Location: messages.php");
    exit;
}

$error = "";
$username = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    check_csrf();
    $username = trim(post_string("username"));
    $password = post_string("password");
    $logName  = mb_substr($username, 0, 30);       // fits the login_attempts column
    $ip       = $_SERVER["REMOTE_ADDR"] ?? "unknown";

    try {
        if (too_many_failures($logName, $ip)) {
            $error = "Too many failed attempts. Wait 15 minutes and try again.";
        } else {
            $stmt = db()->prepare("SELECT id, username, password_hash FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            // Always run password_verify, even for unknown users, so response time gives nothing away.
            $valid = password_verify($password, $user ? $user["password_hash"] : DUMMY_HASH);

            if ($user && $valid) {
                clear_failures($logName);
                log_in($user);
                header("Location: messages.php");
                exit;
            }
            record_failure($logName, $ip);
            // Same message for wrong username and wrong password: attackers learn nothing.
            $error = "Invalid username or password.";
        }
    } catch (PDOException $ex) {
        error_log($ex->getMessage());
        $error = "Login is unavailable right now. Please try again later.";
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Login</title><link rel="stylesheet" href="style.css"></head>
<body>
  <h1>Admin login</h1>

  <?php if (isset($_GET["registered"])): ?>
    <p class="ok">Account created. Please log in.</p>
  <?php endif; ?>
  <?php if ($error): ?>
    <p class="error"><?= e($error) ?></p>
  <?php endif; ?>

  <form method="post">
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <p>Username:<br><input name="username" value="<?= e($username) ?>" autocomplete="username"></p>
    <p>Password:<br><input type="password" name="password" autocomplete="current-password"></p>
    <button type="submit">Log in</button>
  </form>
</body>
</html>