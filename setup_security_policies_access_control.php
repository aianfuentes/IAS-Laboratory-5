<?php
require_once 'config.php';

try {
    // Create security_policies table
    $sql = "CREATE TABLE IF NOT EXISTS security_policies (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        requirements JSON,
        compliance_framework VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )";
    mysqli_query($conn, $sql);

    // Create password_history table
    $sql = "CREATE TABLE IF NOT EXISTS password_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )";
    mysqli_query($conn, $sql);

    // Create security_incidents table
    $sql = "CREATE TABLE IF NOT EXISTS security_incidents (
        id INT AUTO_INCREMENT PRIMARY KEY,
        incident_type VARCHAR(50) NOT NULL,
        severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
        description TEXT,
        response_actions JSON,
        status ENUM('open', 'investigating', 'resolved', 'closed') DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP NULL
    )";
    mysqli_query($conn, $sql);

    // Create policy_violations table
    $sql = "CREATE TABLE IF NOT EXISTS policy_violations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        policy_id INT,
        violation_type VARCHAR(50) NOT NULL,
        description TEXT,
        user_id INT,
        severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
        status ENUM('open', 'investigating', 'resolved', 'closed') DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP NULL,
        FOREIGN KEY (policy_id) REFERENCES security_policies(id) ON DELETE SET NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )";
    mysqli_query($conn, $sql);

    // Create compliance_audit_logs table
    $sql = "CREATE TABLE IF NOT EXISTS compliance_audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        audit_type VARCHAR(50) NOT NULL,
        audit_results JSON,
        status ENUM('pass', 'fail', 'warning') NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INT,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
    )";
    mysqli_query($conn, $sql);

    // Create a default security policy
    $defaultPolicy = [
        'password_requirements' => [
            'min_length' => 12,
            'require_uppercase' => true,
            'require_lowercase' => true,
            'require_numbers' => true,
            'require_special_chars' => true,
            'max_age_days' => 90,
            'password_history' => 5,
            'min_complexity_score' => 3
        ],
        'access_control' => [
            'max_login_attempts' => 5,
            'lockout_duration_minutes' => 30,
            'require_mfa' => true
        ],
        'data_protection' => [
            'encryption_required' => true,
            'backup_frequency_days' => 7,
            'data_retention_days' => 365
        ]
    ];

    $policyName = "Default Security Policy";
    $description = "Comprehensive security policy with strong password requirements and MFA enforcement";
    $requirements = json_encode($defaultPolicy, JSON_PRETTY_PRINT);
    $complianceFramework = "NIST SP 800-63B";

    $sql = "INSERT INTO security_policies (name, description, requirements, compliance_framework) 
            VALUES (?, ?, ?, ?)";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "ssss", $policyName, $description, $requirements, $complianceFramework);
    mysqli_stmt_execute($stmt);

    echo "Security policy tables and default policy created successfully!";
} catch (Exception $e) {
    die("Setup failed: " . $e->getMessage());
}
?> 