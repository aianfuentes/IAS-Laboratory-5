<?php
require_once 'config.php';

try {
    $pdo = new PDO("mysql:host=localhost;dbname=iaslab5", "root", "");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Check security policies
    $stmt = $pdo->query("SELECT * FROM security_policies");
    $policies = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo "<h2>Security Policies in Database:</h2>";
    if (empty($policies)) {
        echo "<p>No policies found in the database.</p>";
    } else {
        foreach ($policies as $policy) {
            echo "<div style='margin-bottom: 20px; padding: 10px; border: 1px solid #ccc;'>";
            echo "<h3>Policy: " . htmlspecialchars($policy['name']) . "</h3>";
            echo "<p><strong>Description:</strong> " . htmlspecialchars($policy['description']) . "</p>";
            echo "<p><strong>Compliance Framework:</strong> " . htmlspecialchars($policy['compliance_framework']) . "</p>";
            echo "<p><strong>Requirements:</strong></p>";
            echo "<pre>" . json_encode(json_decode($policy['requirements']), JSON_PRETTY_PRINT) . "</pre>";
            echo "</div>";
        }
    }

    // Check if password policy is being enforced
    echo "<h2>Testing Password Policy:</h2>";
    echo "<p>Try registering a new user with these test passwords:</p>";
    echo "<ul>";
    echo "<li>Weak password (should fail): 'password123'</li>";
    echo "<li>Strong password (should pass): 'StrongP@ssw0rd123'</li>";
    echo "</ul>";
    echo "<p>Visit <a href='register.php'>register.php</a> to test the password policy.</p>";

} catch(PDOException $e) {
    echo "Error: " . $e->getMessage();
}
?> 