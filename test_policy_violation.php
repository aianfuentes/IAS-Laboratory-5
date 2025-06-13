<?php
require_once 'config.php';
require_once 'password_policy.php';

// Function to create a test user
function createTestUser($username) {
    global $conn;
    
    // Check if user already exists
    $stmt = mysqli_prepare($conn, "SELECT id FROM users WHERE username = ?");
    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    if (mysqli_num_rows($result) == 0) {
        // Create user with a valid password
        $password = 'Test@123456';
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = mysqli_prepare($conn, "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')");
        mysqli_stmt_bind_param($stmt, 'ss', $username, $hashedPassword);
        mysqli_stmt_execute($stmt);
        echo "Created test user: $username<br>";
    }
}

// Function to check if violation already exists
function violationExists($username, $description) {
    global $conn;
    
    $stmt = mysqli_prepare($conn, "SELECT id FROM policy_violations WHERE username = ? AND description = ? AND status = 'open'");
    mysqli_stmt_bind_param($stmt, 'ss', $username, $description);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    return mysqli_num_rows($result) > 0;
}

// Function to log policy violation
function logPolicyViolation($username, $description, $severity = 'medium') {
    global $conn;
    
    // Check if this violation already exists
    if (violationExists($username, $description)) {
        return false;
    }
    
    // Get the password policy ID
    $stmt = mysqli_prepare($conn, "SELECT id FROM security_policies WHERE policy_name = 'Password Policy'");
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $policy = mysqli_fetch_assoc($result);
    
    if ($policy) {
        $stmt = mysqli_prepare($conn, "INSERT INTO policy_violations (policy_id, username, description, severity) VALUES (?, ?, ?, ?)");
        mysqli_stmt_bind_param($stmt, 'isss', $policy['id'], $username, $description, $severity);
        return mysqli_stmt_execute($stmt);
    }
    return false;
}

// Test cases
$test_cases = [
    [
        'username' => 'testuser1',
        'password' => 'weak',  // Too short, no uppercase, no numbers, no special chars
        'expected_violation' => 'Password does not meet minimum length requirement (12 characters)'
    ],
    [
        'username' => 'testuser2',
        'password' => 'password123',  // No uppercase, no special chars
        'expected_violation' => 'Password must contain at least one uppercase letter and one special character'
    ],
    [
        'username' => 'testuser3',
        'password' => 'PASSWORD123',  // No lowercase, no special chars
        'expected_violation' => 'Password must contain at least one lowercase letter and one special character'
    ]
];

// Create test users first
echo "<h2>Creating Test Users</h2>";
foreach ($test_cases as $test) {
    createTestUser($test['username']);
}
echo "<hr>";

$passwordPolicy = new PasswordPolicy();

echo "<h2>Testing Policy Violations</h2>";

foreach ($test_cases as $test) {
    echo "<h3>Testing: {$test['username']}</h3>";
    echo "Password: {$test['password']}<br>";
    
    // Validate password
    $validation = $passwordPolicy->validatePassword($test['password'], $test['username']);
    
    if (!$validation['valid']) {
        echo "Policy Violation Detected:<br>";
        foreach ($validation['errors'] as $error) {
            echo "- $error<br>";
            // Log the violation if it doesn't already exist
            if (logPolicyViolation($test['username'], $error)) {
                echo "  (New violation logged)<br>";
            } else {
                echo "  (Violation already exists)<br>";
            }
        }
    } else {
        echo "Password meets all requirements<br>";
    }
    echo "<hr>";
}

echo "<p>Check the admin dashboard to see these violations.</p>";
echo "<a href='admin_dashboard.php'>Go to Admin Dashboard</a>";
?> 