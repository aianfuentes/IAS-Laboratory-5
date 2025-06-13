<?php
require_once 'config.php';

// Add mfa_secret column to users table
$sql = "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(32)";
mysqli_query($conn, $sql);

echo "Database updated successfully!";
?> 