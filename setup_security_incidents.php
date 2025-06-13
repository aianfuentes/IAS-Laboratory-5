<?php
require_once 'config.php';

try {
    // Connect to the database
    $conn = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, 'iaslab5');
    if (!$conn) {
        throw new Exception("Database connection failed: " . mysqli_connect_error());
    }

    // Create security_incidents table
    $sql = "CREATE TABLE IF NOT EXISTS security_incidents (
        id INT AUTO_INCREMENT PRIMARY KEY,
        incident_type VARCHAR(50) NOT NULL,
        severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
        description TEXT NOT NULL,
        response_actions JSON,
        status ENUM('open', 'investigating', 'resolved', 'closed') DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP NULL
    )";

    if (mysqli_query($conn, $sql)) {
        echo "Security incidents table created successfully!";
    } else {
        throw new Exception("Error creating security incidents table: " . mysqli_error($conn));
    }

} catch (Exception $e) {
    die("Setup failed: " . $e->getMessage());
}
?> 