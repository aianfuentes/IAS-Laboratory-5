<?php
session_start();
require_once 'config.php';

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}

// Check if violation ID is provided
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    $_SESSION['error'] = "Invalid violation ID.";
    header('Location: admin_dashboard.php');
    exit();
}

$violation_id = $_GET['id'];

// Delete the violation
$stmt = $conn->prepare("DELETE FROM policy_violations WHERE id = ?");
$stmt->bind_param("i", $violation_id);

if ($stmt->execute()) {
    $_SESSION['success'] = "Policy violation has been deleted successfully.";
} else {
    $_SESSION['error'] = "Failed to delete policy violation.";
}

header('Location: admin_dashboard.php');
exit();
?> 