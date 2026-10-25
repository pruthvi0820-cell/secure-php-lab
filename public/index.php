<?php require __DIR__ . "/../src/bootstrap.php"; ?>
<!DOCTYPE html>
<html>
<head><title>My PHP Lab</title></head>
<body>
  <h1>Hello from PHP!</h1>

  <?php
    $name = "Pruthvi";
    $city = "Bengaluru";
    $skills = ["SQL", "Python", "Power BI", "PHP", "data modeling", "RAG"];

    echo "<p>My name is $name.</p>";
    echo "<p>I Live in $city.</p>";
    echo "<p>Server time: " . date("d M Y, H:i:s") . "</p>";
    echo "<p>PHP version: " . PHP_VERSION . "</p>";

    echo "<h2>My skills</h2><ul>";
    foreach ($skills as $skill) {
        echo "<li>$skill</li>";
    }
    echo "</ul>";

    // Read ?visitor=... from the URL, and make it safe before showing it
    $visitor = $_GET["visitor"] ?? "guest";
    echo "<p>Welcome, " . htmlspecialchars($visitor) . "!</p>";
    if ($visitor == "Recruiter") {
    echo "<p>Thanks for checking my profile!</p>";
} else {
    echo "<p>Welcome, guest!</p>";
}
  ?>
</body>
</html>