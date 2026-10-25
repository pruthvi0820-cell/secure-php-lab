<?php
// Creates the FIRST account only (the admin). After that, registration is closed.
require __DIR__ . "/../src/bootstrap.php";

start_session();
$errors = [];
$username = "";
$closed = false;

try {
    $closed = (int) db()->query("SELECT COUNT(*) FROM users")->fetchColumn() > 0;
} catch (PDOException $ex) {
    error_log($ex->getMessage());
    $errors[] = "Registration is unavailable right now. Please try again later.";
}

if (!$closed && empty($errors) && $_SERVER["REQUEST_METHOD"] === "POST") {
    check_csrf();
    $username = trim(post_string("username"));
    $password = post_string("password");
    $confirm  = post_string("confirm");

    if (!preg_match('/^[A-Za-z0-9_]{3,30}$/', $username)) {
        $errors[] = "Username: 3-30 letters, numbers or underscores.";
    }
    if (strlen($password) < 12) {
        $errors[] = "Password must be at least 12 characters.";
    }
    if (strlen($password) > 72) {
        $errors[] = "Password must be at most 72 characters.";   // bcrypt ignores anything longer
    }
    if ($password !== $confirm) {
        $errors[] = "Passwords do not match.";
    }

    if (empty($errors)) {
        try {
            $hash = password_hash($password, PASSWORD_BCRYPT, ["cost" => PASSWORD_COST]);
            db()->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")->execute([$username, $hash]);
            header("Location: login.php?registered=1");
            exit;
        } catch (PDOException $ex) {
            error_log($ex->getMessage());
            $errors[] = "Could not create the account. Please try again.";
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Create admin account</title><link rel="stylesheet" href="style.css"></head>
<body>
  <h1>Create admin account</h1>

  <?php if ($closed): ?>
    <p>Registration is closed. The admin account already exists.</p>
    <p><a href="login.php">Go to login</a></p>
  <?php else: ?>

    <?php foreach ($errors as $err): ?>
      <p class="error"><?= e($err) ?></p>
    <?php endforeach; ?>

    <form method="post">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <p>Username:<br><input name="username" value="<?= e($username) ?>" autocomplete="username"></p>
      <p>Password (12+ characters):<br><input type="password" name="password" autocomplete="new-password"></p>
      <p>Confirm password:<br><input type="password" name="confirm" autocomplete="new-password"></p>
      <button type="submit">Create account</button>
    </form>

  <?php endif; ?>
</body>
</html>