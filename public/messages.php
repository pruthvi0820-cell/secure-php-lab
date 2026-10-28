<?php
require __DIR__ . "/../src/bootstrap.php";
$user = require_login();
// Set by the gateway after Authelia verified password + phone code. The gateway overwrites any value a
// visitor sends, and PHP cannot be reached except through the gateway, so this can be trusted here.
$gatewayUser = $_SERVER["HTTP_REMOTE_USER"] ?? "";

$q = trim($_GET["q"] ?? "");
$rows = [];
$error = "";
try {
    if ($q === "") {
        $rows = db()->query("SELECT name, email, phone, message, created_at FROM messages ORDER BY id DESC LIMIT 50")->fetchAll();
    } else {
        $stmt = db()->prepare("SELECT name, email, phone, message, created_at FROM messages WHERE name = ? ORDER BY id DESC");
        $stmt->execute([$q]);           // input is sent separately as DATA, never mixed into the SQL
        $rows = $stmt->fetchAll();
    }
} catch (PDOException $ex) {
    error_log($ex->getMessage());
    $error = "Database error. Please try again later.";
}
?>
<!DOCTYPE html>
<html>
<head><title>Messages</title><link rel="stylesheet" href="style.css"></head>
<body>
  <h1>Messages</h1>
  <div>
    Logged in as <b><?= e($user["username"]) ?></b>
    <?php if ($gatewayUser !== ""): ?>
      &middot; verified by the security gateway (password + phone code) as <b><?= e($gatewayUser) ?></b>
    <?php endif; ?>
    <form method="post" action="logout.php" class="inline">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <button type="submit">Log out</button>
    </form>
  </div>
  <form method="get">
    <input name="q" value="<?= e($q) ?>" placeholder="Search by name">
    <button>Search</button>
  </form>

  <?php if ($error): ?><p class="error"><?= e($error) ?></p><?php endif; ?>

  <table>
    <tr><th>Name</th><th>Email</th><th>Phone</th><th>Message</th><th>When</th></tr>
    <?php foreach ($rows as $r): ?>
      <tr><td><?= e($r["name"]) ?></td><td><?= e($r["email"]) ?></td><td><?= e($r["phone"]) ?></td>
          <td><?= e($r["message"]) ?></td><td><?= e($r["created_at"]) ?></td></tr>
    <?php endforeach; ?>
  </table>
  <p><?= count($rows) ?> message(s)</p>
</body>
</html>