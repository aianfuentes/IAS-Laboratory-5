<?php
function checkPermission($requiredRole) {
    if (isset($_SESSION['role']) && $_SESSION['role'] === $requiredRole) {
        return true;
    }
    return false;
}
?> 