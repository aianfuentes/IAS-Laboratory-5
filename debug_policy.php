<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h1>Database and Policy Debug Information</h1>";

try {
    // Test database connection
    echo "<h2>Testing Database Connection</h2>";
    $pdo = new PDO("mysql:host=localhost;dbname=iaslab5", "root", "");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "<div style='color: green;'>✓ Database connection successful</div>";

    // Check if tables exist
    echo "<h2>Checking Database Tables</h2>";
    $tables = ['security_policies', 'users', 'password_history', 'security_incidents', 'policy_violations', 'compliance_audit_logs'];
    
    foreach ($tables as $table) {
        $stmt = $pdo->query("SHOW TABLES LIKE '$table'");
        if ($stmt->rowCount() > 0) {
            echo "<div style='color: green;'>✓ Table '$table' exists</div>";
        } else {
            echo "<div style='color: red;'>✗ Table '$table' does not exist</div>";
        }
    }

    // Check security_policies table structure
    echo "<h2>Security Policies Table Structure</h2>";
    $stmt = $pdo->query("DESCRIBE security_policies");
    echo "<pre>";
    print_r($stmt->fetchAll(PDO::FETCH_ASSOC));
    echo "</pre>";

    // Check existing policies
    echo "<h2>Existing Policies</h2>";
    $stmt = $pdo->query("SELECT * FROM security_policies");
    $policies = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if (empty($policies)) {
        echo "<div style='color: orange;'>No policies found in database</div>";
    } else {
        echo "<pre>";
        print_r($policies);
        echo "</pre>";
    }

    // Test policy creation
    echo "<h2>Testing Policy Creation</h2>";
    $testPolicy = [
        'name' => 'Test Policy',
        'description' => 'Test policy for debugging',
        'requirements' => json_encode([
            'password_requirements' => [
                'min_length' => 12,
                'require_uppercase' => true
            ]
        ]),
        'compliance_framework' => 'Test Framework'
    ];

    $sql = "INSERT INTO security_policies (name, description, requirements, compliance_framework) 
            VALUES (?, ?, ?, ?)";
    $stmt = $pdo->prepare($sql);
    
    try {
        $result = $stmt->execute([
            $testPolicy['name'],
            $testPolicy['description'],
            $testPolicy['requirements'],
            $testPolicy['compliance_framework']
        ]);
        
        if ($result) {
            echo "<div style='color: green;'>✓ Test policy created successfully</div>";
            
            // Verify the policy was created
            $stmt = $pdo->query("SELECT * FROM security_policies WHERE name = 'Test Policy'");
            $createdPolicy = $stmt->fetch(PDO::FETCH_ASSOC);
            echo "<pre>";
            print_r($createdPolicy);
            echo "</pre>";
        } else {
            echo "<div style='color: red;'>✗ Failed to create test policy</div>";
        }
    } catch (PDOException $e) {
        echo "<div style='color: red;'>✗ Error creating test policy: " . $e->getMessage() . "</div>";
    }

} catch (PDOException $e) {
    echo "<div style='color: red;'>✗ Database Error: " . $e->getMessage() . "</div>";
}
?> 