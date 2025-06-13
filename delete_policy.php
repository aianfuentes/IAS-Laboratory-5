<?php
session_start();
require_once 'config.php';

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    $_SESSION['error'] = "You must be logged in as an admin to delete policies.";
    header('Location: index.php');
    exit();
}

// Check if policy ID is provided
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    $_SESSION['error'] = "Invalid policy ID.";
    header('Location: security_policy_management.php');
    exit();
}

$policy_id = (int)$_GET['id'];

try {
    // Connect to the correct database
    $conn = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, 'iaslab5');
    if (!$conn) {
        throw new Exception("Database connection failed: " . mysqli_connect_error());
    }

    // First check if the policy exists
    $check_stmt = $conn->prepare("SELECT id FROM security_policies WHERE id = ?");
    $check_stmt->bind_param("i", $policy_id);
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    
    if ($result->num_rows === 0) {
        $_SESSION['error'] = "Policy not found.";
        header('Location: security_policy_management.php');
        exit();
    }

    // Begin transaction
    $conn->begin_transaction();

    // Delete related policy violations first
    $delete_violations = $conn->prepare("DELETE FROM policy_violations WHERE policy_id = ?");
    $delete_violations->bind_param("i", $policy_id);
    $delete_violations->execute();

    // Delete the policy
    $delete_policy = $conn->prepare("DELETE FROM security_policies WHERE id = ?");
    $delete_policy->bind_param("i", $policy_id);
    $delete_policy->execute();

    // Check if the policy was actually deleted
    if ($delete_policy->affected_rows === 0) {
        throw new Exception("Failed to delete policy. No rows were affected.");
    }

    // Commit transaction
    $conn->commit();

    $_SESSION['success'] = "Policy and related violations have been successfully deleted.";
} catch (Exception $e) {
    // Rollback transaction on error
    if (isset($conn)) {
        $conn->rollback();
    }
    error_log("Error deleting policy: " . $e->getMessage());
    $_SESSION['error'] = "Error deleting policy: " . $e->getMessage();
}

header('Location: security_policy_management.php');
exit();
?> 