<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

try {
    // Connect to both databases
    $source_pdo = new PDO("mysql:host=localhost;dbname=iaslab5", "root", "");
    $source_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $target_conn = mysqli_connect("localhost", "root", "", "access_control_db");
    if (!$target_conn) {
        throw new Exception("Failed to connect to access_control_db: " . mysqli_connect_error());
    }

    echo "<h2>Starting Migration</h2>";

    // Create necessary tables in access_control_db
    echo "<h3>Creating Tables</h3>";
    
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
    mysqli_query($target_conn, $sql);
    echo "✓ Created security_policies table<br>";

    // Create password_history table
    $sql = "CREATE TABLE IF NOT EXISTS password_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )";
    mysqli_query($target_conn, $sql);
    echo "✓ Created password_history table<br>";

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
    mysqli_query($target_conn, $sql);
    echo "✓ Created security_incidents table<br>";

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
    mysqli_query($target_conn, $sql);
    echo "✓ Created policy_violations table<br>";

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
    mysqli_query($target_conn, $sql);
    echo "✓ Created compliance_audit_logs table<br>";

    // Migrate security policies
    echo "<h3>Migrating Security Policies</h3>";
    $stmt = $source_pdo->query("SELECT * FROM security_policies");
    $policies = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($policies as $policy) {
        $sql = "INSERT INTO security_policies (name, description, requirements, compliance_framework, created_at, updated_at) 
                VALUES (?, ?, ?, ?, ?, ?)";
        $stmt = mysqli_prepare($target_conn, $sql);
        mysqli_stmt_bind_param($stmt, "ssssss", 
            $policy['name'],
            $policy['description'],
            $policy['requirements'],
            $policy['compliance_framework'],
            $policy['created_at'],
            $policy['updated_at']
        );
        mysqli_stmt_execute($stmt);
        echo "✓ Migrated policy: " . htmlspecialchars($policy['name']) . "<br>";
    }

    // Migrate password history
    echo "<h3>Migrating Password History</h3>";
    $stmt = $source_pdo->query("SELECT * FROM password_history");
    $history = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($history as $entry) {
        $sql = "INSERT INTO password_history (username, password, created_at) VALUES (?, ?, ?)";
        $stmt = mysqli_prepare($target_conn, $sql);
        mysqli_stmt_bind_param($stmt, "sss", 
            $entry['username'],
            $entry['password'],
            $entry['created_at']
        );
        mysqli_stmt_execute($stmt);
        echo "✓ Migrated password history for user: " . htmlspecialchars($entry['username']) . "<br>";
    }

    // Migrate security incidents
    echo "<h3>Migrating Security Incidents</h3>";
    $stmt = $source_pdo->query("SELECT * FROM security_incidents");
    $incidents = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($incidents as $incident) {
        $sql = "INSERT INTO security_incidents (incident_type, severity, description, response_actions, status, created_at, resolved_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?)";
        $stmt = mysqli_prepare($target_conn, $sql);
        mysqli_stmt_bind_param($stmt, "sssssss", 
            $incident['incident_type'],
            $incident['severity'],
            $incident['description'],
            $incident['response_actions'],
            $incident['status'],
            $incident['created_at'],
            $incident['resolved_at']
        );
        mysqli_stmt_execute($stmt);
        echo "✓ Migrated incident: " . htmlspecialchars($incident['incident_type']) . "<br>";
    }

    // Migrate policy violations
    echo "<h3>Migrating Policy Violations</h3>";
    $stmt = $source_pdo->query("SELECT * FROM policy_violations");
    $violations = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($violations as $violation) {
        $sql = "INSERT INTO policy_violations (policy_id, violation_type, description, user_id, severity, status, created_at, resolved_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        $stmt = mysqli_prepare($target_conn, $sql);
        mysqli_stmt_bind_param($stmt, "ississss", 
            $violation['policy_id'],
            $violation['violation_type'],
            $violation['description'],
            $violation['user_id'],
            $violation['severity'],
            $violation['status'],
            $violation['created_at'],
            $violation['resolved_at']
        );
        mysqli_stmt_execute($stmt);
        echo "✓ Migrated violation: " . htmlspecialchars($violation['violation_type']) . "<br>";
    }

    // Migrate compliance audit logs
    echo "<h3>Migrating Compliance Audit Logs</h3>";
    $stmt = $source_pdo->query("SELECT * FROM compliance_audit_logs");
    $audits = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($audits as $audit) {
        $sql = "INSERT INTO compliance_audit_logs (audit_type, audit_results, status, created_at, created_by) 
                VALUES (?, ?, ?, ?, ?)";
        $stmt = mysqli_prepare($target_conn, $sql);
        mysqli_stmt_bind_param($stmt, "ssssi", 
            $audit['audit_type'],
            $audit['audit_results'],
            $audit['status'],
            $audit['created_at'],
            $audit['created_by']
        );
        mysqli_stmt_execute($stmt);
        echo "✓ Migrated audit log: " . htmlspecialchars($audit['audit_type']) . "<br>";
    }

    echo "<h2>Migration Completed Successfully!</h2>";

} catch (Exception $e) {
    die("Migration failed: " . $e->getMessage());
}
?> 