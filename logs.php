<?php
require_once 'config.php';

function logAccess($user, $action, $status) {
    global $conn;
    
    // Log to database
    $sql = "INSERT INTO access_logs (user_id, action, status, ip_address, timestamp) 
            VALUES (?, ?, ?, ?, NOW())";
    $stmt = mysqli_prepare($conn, $sql);
    $ip = $_SERVER['REMOTE_ADDR'];
    mysqli_stmt_bind_param($stmt, "isss", $user, $action, $status, $ip);
    mysqli_stmt_execute($stmt);
    
    // Log to file
    $logFile = 'access_log.txt';
    $logEntry = date('Y-m-d H:i:s') . " - User: $user, Action: $action, Status: $status, IP: $ip\n";
    file_put_contents($logFile, $logEntry, FILE_APPEND);
}

function detectIntrusion() {
    global $conn;
    
    // Check for multiple failed login attempts
    $sql = "SELECT COUNT(*) as failed_attempts 
            FROM access_logs 
            WHERE status = 'failed' 
            AND timestamp > DATE_SUB(NOW(), INTERVAL 15 MINUTE)";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_assoc($result);
    
    if ($row['failed_attempts'] >= 5) {
        // Potential intrusion detected
        logAccess('SYSTEM', 'INTRUSION_DETECTED', 'multiple_failed_attempts');
        return true;
    }
    
    return false;
}

function generateSecurityReport() {
    global $conn;
    
    $report = [];
    
    // Get failed login attempts
    $sql = "SELECT COUNT(*) as failed_count 
            FROM access_logs 
            WHERE status = 'failed' 
            AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_assoc($result);
    $report['failed_attempts'] = $row['failed_count'];
    
    // Get successful logins
    $sql = "SELECT COUNT(*) as success_count 
            FROM access_logs 
            WHERE status = 'success' 
            AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_assoc($result);
    $report['successful_logins'] = $row['success_count'];
    
    // Get MFA statistics
    $sql = "SELECT COUNT(*) as mfa_count 
            FROM access_logs 
            WHERE action = 'MFA_VERIFICATION' 
            AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_assoc($result);
    $report['mfa_verifications'] = $row['mfa_count'];
    
    return $report;
}

// Create the access_logs table if it doesn't exist
$sql = "CREATE TABLE IF NOT EXISTS access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    timestamp DATETIME NOT NULL
)";
mysqli_query($conn, $sql);
?> 