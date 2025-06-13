<?php
// Get user information if not already set
if (!isset($user)) {
    $user_id = $_SESSION['user_id'];
    $stmt = $conn->prepare("SELECT username, role FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
}
?>

<!-- Main Sidebar Container -->
<aside class="main-sidebar sidebar-dark-primary elevation-4">
    <!-- Brand Logo -->
    <a href="admin_dashboard.php" class="brand-link">
        <i class="fas fa-shield-alt brand-image img-circle elevation-3" style="opacity: .8"></i>
        <span class="brand-text font-weight-light">Access Control</span>
    </a>

    <!-- Sidebar -->
    <div class="sidebar">
        <!-- Sidebar user panel -->
        <div class="user-panel mt-3 pb-3 mb-3 d-flex">
            <div class="image">
                <i class="fas fa-user-circle fa-2x text-light"></i>
            </div>
            <div class="info">
                <a href="#" class="d-block"><?php echo htmlspecialchars($user['username']); ?></a>
            </div>
        </div>

        <!-- Sidebar Menu -->
        <nav class="mt-2">
            <ul class="nav nav-pills nav-sidebar flex-column" data-widget="treeview" role="menu">
                <li class="nav-item">
                    <a href="admin_dashboard.php" class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'admin_dashboard.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-tachometer-alt"></i>
                        <p>Dashboard</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="security_policy_management.php" class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'security_policy_management.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-shield-alt"></i>
                        <p>Security Policies</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="view_violations.php" class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'view_violations.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-exclamation-triangle"></i>
                        <p>Policy Violations</p>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="user_management.php" class="nav-link <?php echo basename($_SERVER['PHP_SELF']) == 'user_management.php' ? 'active' : ''; ?>">
                        <i class="nav-icon fas fa-users"></i>
                        <p>User Management</p>
                    </a>
                </li>
                <li class="nav-header">RECENT SECURITY INCIDENTS</li>
                <?php if (isset($recent_incidents) && !empty($recent_incidents)): ?>
                    <?php foreach ($recent_incidents as $incident): ?>
                    <li class="nav-item">
                        <a href="security_incidents.php?id=<?php echo $incident['id']; ?>" class="nav-link">
                            <i class="nav-icon fas fa-exclamation-circle text-<?php 
                                echo $incident['severity'] === 'critical' ? 'danger' : 
                                    ($incident['severity'] === 'high' ? 'warning' : 
                                    ($incident['severity'] === 'medium' ? 'info' : 'secondary')); 
                            ?>"></i>
                            <p>
                                <?php echo htmlspecialchars(substr($incident['description'], 0, 30)) . '...'; ?>
                                <small class="text-muted d-block">
                                    <?php echo date('M d, H:i', strtotime($incident['created_at'])); ?>
                                </small>
                            </p>
                        </a>
                    </li>
                    <?php endforeach; ?>
                <?php else: ?>
                    <li class="nav-item">
                        <a href="#" class="nav-link">
                            <i class="nav-icon fas fa-check-circle text-success"></i>
                            <p>No recent incidents</p>
                        </a>
                    </li>
                <?php endif; ?>
            </ul>
        </nav>
    </div>
</aside> 