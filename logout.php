<?php
session_start();
require_once 'logs.php';

// Log the logout
if (isset($_SESSION['username'])) {
    logAccess($_SESSION['username'], 'LOGOUT', 'success');
}

// Destroy the session
session_destroy();

// Redirect to login page
header('Location: index.php');
exit();
?> 