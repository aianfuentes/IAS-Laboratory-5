<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

try {
    // Test database connection
    $pdo = new PDO("mysql:host=localhost;dbname=iaslab5", "root", "");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "<h2>Database Connection</h2>";
    echo "<div style='color: green;'>✓ Connected successfully</div>";

    // Test policy creation
    echo "<h2>Testing Policy Creation</h2>";
    
    $policy = [
        'name' => 'GDPR Compliance Policy',
        'description' => 'Comprehensive security policy ensuring GDPR compliance with strong password requirements, data protection measures, and privacy controls',
        'requirements' => json_encode([
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
                'require_mfa' => false
            ],
            'data_protection' => [
                'encryption_required' => true,
                'backup_frequency_days' => 7,
                'data_retention_days' => 365,
                'right_to_be_forgotten' => true,
                'data_portability' => true,
                'privacy_by_design' => true
            ],
            'gdpr_specific' => [
                'consent_management' => true,
                'data_breach_notification' => true,
                'data_processing_records' => true,
                'privacy_impact_assessment' => true,
                'data_protection_officer' => true
            ]
        ], JSON_PRETTY_PRINT),
        'compliance_framework' => 'GDPR'
    ];

    // Print the policy data
    echo "<h3>Policy Data:</h3>";
    echo "<pre>";
    print_r($policy);
    echo "</pre>";

    // Insert the policy
    $sql = "INSERT INTO security_policies (name, description, requirements, compliance_framework) 
            VALUES (?, ?, ?, ?)";
    $stmt = $pdo->prepare($sql);
    
    try {
        $result = $stmt->execute([
            $policy['name'],
            $policy['description'],
            $policy['requirements'],
            $policy['compliance_framework']
        ]);
        
        if ($result) {
            echo "<div style='color: green;'>✓ Policy created successfully</div>";
            
            // Verify the policy was created
            $stmt = $pdo->query("SELECT * FROM security_policies WHERE name = 'GDPR Compliance Policy'");
            $createdPolicy = $stmt->fetch(PDO::FETCH_ASSOC);
            echo "<h3>Created Policy:</h3>";
            echo "<pre>";
            print_r($createdPolicy);
            echo "</pre>";
        } else {
            echo "<div style='color: red;'>✗ Failed to create policy</div>";
        }
    } catch (PDOException $e) {
        echo "<div style='color: red;'>✗ Error creating policy: " . $e->getMessage() . "</div>";
    }

} catch (PDOException $e) {
    echo "<div style='color: red;'>✗ Database Error: " . $e->getMessage() . "</div>";
}
?> 