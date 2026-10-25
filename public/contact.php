<?php
require __DIR__ . "/../src/bootstrap.php";

$errors = [];
$name = $email = $phone = $message = "";
$sent = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // 1. Read input and trim extra spaces
    $name    = trim(post_string("name"));
    $email   = trim(post_string("email"));
    $phone   = trim(post_string("phone"));
    $message = trim(post_string("message"));

    // 2. Validate: never trust what the user sends
    if ($name === "" || mb_strlen($name) > 50) {
        $errors[] = "Name is required (max 50 characters).";
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Please enter a valid email.";
    }
    if (!preg_match('/^[0-9]{10}$/', $phone)) {
        $errors[] = "Phone must be 10 digits.";
    }
    if (mb_strlen($message) < 10) {
        $errors[] = "Message must be at least 10 characters.";
    }

    // 3. Save with a prepared statement
    if (empty($errors)) {
        try {
            $stmt = db()->prepare("INSERT INTO messages (name, email, phone, message) VALUES (?, ?, ?, ?)");
            $stmt->execute([$name, $email, $phone, $message]);
            $sent = true;
        } catch (PDOException $ex) {
            error_log($ex->getMessage());          // details go to the server log, never to the visitor
            $errors[] = "Could not save your message. Please try again later.";
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Contact</title><link rel="stylesheet" href="style.css"></head>
<body>
  <h1>Contact me</h1>

  <?php if ($sent): ?>
    <p class="ok">Thanks, <?= e($name) ?>! I will reply to <?= e($email) ?>.</p>
  <?php else: ?>

    <?php foreach ($errors as $err): ?>
      <p class="error"><?= e($err) ?></p>
    <?php endforeach; ?>

    <form method="post">
      <p>Name:<br><input name="name" value="<?= e($name) ?>"></p>
      <p>Email:<br><input name="email" value="<?= e($email) ?>"></p>
      <p>Phone (10 digits):<br><input name="phone" value="<?= e($phone) ?>"></p>
      <p>Message:<br><textarea name="message" rows="4" cols="40"><?= e($message) ?></textarea></p>
      <button type="submit">Send</button>
    </form>

  <?php endif; ?>
</body>
</html>