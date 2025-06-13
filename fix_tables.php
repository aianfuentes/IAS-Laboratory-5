<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

try {
    $pdo = new PDO("mysql:host=localhost;dbname=iaslab5", "root", "");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Fix security_incidents table
    $pdo->exec("ALTER TABLE security_incidents 
                ADD COLUMN IF NOT EXISTS reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");

    // Fix policy_violations table
    $pdo->exec("ALTER TABLE policy_violations 
                ADD COLUMN IF NOT EXISTS violated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");

    // Clear existing test policies
    $pdo->exec("DELETE FROM security_policies WHERE name = 'Test Policy'");

    echo "Database tables fixed successfully!";
} catch (PDOException $e) {
    echo "Error: " . $e->getMessage();
}
?> 