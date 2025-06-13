<?php
require_once 'config.php';

// Drop existing tables if they exist (to ensure clean setup)
$sql = "DROP TABLE IF EXISTS policy_violations";
mysqli_query($conn, $sql);

$sql = "DROP TABLE IF EXISTS security_policies";
mysqli_query($conn, $sql);

// Create security_policies table
$sql = "CREATE TABLE security_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_name VARCHAR(255) NOT NULL,
    description TEXT,
    requirements JSON,
    compliance_framework VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)";

if (mysqli_query($conn, $sql)) {
    echo "Security policies table created successfully<br>";
} else {
    echo "Error creating security policies table: " . mysqli_error($conn) . "<br>";
    exit();
}

// Create policy_violations table
$sql = "CREATE TABLE policy_violations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_id INT,
    username VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('low', 'medium', 'high') NOT NULL DEFAULT 'medium',
    status ENUM('open', 'resolved', 'investigating') NOT NULL DEFAULT 'open',
    violation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolution_date TIMESTAMP NULL,
    resolution_notes TEXT,
    FOREIGN KEY (policy_id) REFERENCES security_policies(id) ON DELETE SET NULL,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
)";

if (mysqli_query($conn, $sql)) {
    echo "Policy violations table created successfully<br>";
} else {
    echo "Error creating policy violations table: " . mysqli_error($conn) . "<br>";
    exit();
}

// Insert default password policy
$default_policy = [
    'min_length' => 12,
    'require_uppercase' => true,
    'require_lowercase' => true,
    'require_numbers' => true,
    'require_special_chars' => true,
    'max_age_days' => 90,
    'password_history' => 5
];

$requirements_json = json_encode($default_policy);

$sql = "INSERT INTO security_policies (policy_name, description, requirements, compliance_framework) 
        VALUES ('Password Policy', 'Default password policy for all users', ?, 'NIST SP 800-63B')";

$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, 's', $requirements_json);

if (mysqli_stmt_execute($stmt)) {
    echo "Default password policy created successfully<br>";
} else {
    echo "Error creating default password policy: " . mysqli_error($conn) . "<br>";
}

echo "Setup completed!";
?> 