<?php
session_start();
require_once 'config.php';

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}

// Get user information
$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT username, role FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

// Get total users count
$stmt = $conn->prepare("SELECT COUNT(*) as total FROM users");
$stmt->execute();
$result = $stmt->get_result();
$total_users = $result->fetch_assoc()['total'];

// Get total policies count
$stmt = $conn->prepare("SELECT COUNT(*) as total FROM security_policies");
$stmt->execute();
$result = $stmt->get_result();
$total_policies = $result->fetch_assoc()['total'];

// Get total violations count
$stmt = $conn->prepare("SELECT COUNT(*) as total FROM policy_violations");
$stmt->execute();
$result = $stmt->get_result();
$total_violations = $result->fetch_assoc()['total'];

// Get recent policy violations
$stmt = $conn->prepare("
    SELECT pv.*, sp.policy_name 
    FROM policy_violations pv 
    JOIN security_policies sp ON pv.policy_id = sp.id 
    WHERE pv.status = 'open' 
    ORDER BY pv.violation_date DESC 
    LIMIT 5
");
$stmt->execute();
$recent_violations = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Get recent access logs
$stmt = $conn->prepare("
    SELECT al.*, u.username 
        FROM access_logs al 
        LEFT JOIN users u ON al.user_id = u.id 
    ORDER BY al.timestamp DESC 
    LIMIT 5
");
$stmt->execute();
$recent_logs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Get recent security incidents
$stmt = $conn->prepare("
    SELECT * FROM security_incidents 
    ORDER BY created_at DESC 
    LIMIT 5
");
$stmt->execute();
$recent_incidents = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Include header
include 'includes/header.php';

// Include sidebar
include 'includes/sidebar.php';
?>

<!-- Content Wrapper -->
<div class="content-wrapper">
    <!-- Content Header -->
    <div class="content-header">
        <div class="container-fluid">
            <div class="row mb-2">
                <div class="col-sm-6">
                    <h1 class="m-0">Dashboard</h1>
                </div>
            </div>
        </div>
    </div>

    <!-- Main content -->
    <div class="content">
        <div class="container-fluid">
            <?php if (isset($_SESSION['success'])): ?>
                <div class="alert alert-success alert-dismissible">
                    <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
                    <?php 
                    echo $_SESSION['success'];
                    unset($_SESSION['success']);
                    ?>
                </div>
            <?php endif; ?>

            <?php if (isset($_SESSION['error'])): ?>
                <div class="alert alert-danger alert-dismissible">
                    <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
                    <?php 
                    echo $_SESSION['error'];
                    unset($_SESSION['error']);
                    ?>
                </div>
            <?php endif; ?>

            <!-- Info boxes -->
            <div class="row">
                <div class="col-lg-4 col-6">
                    <div class="small-box bg-info">
                        <div class="inner">
                            <h3><?php echo $total_users; ?></h3>
                            <p>Total Users</p>
                        </div>
                        <div class="icon">
                            <i class="fas fa-users"></i>
                        </div>
                        <a href="user_management.php" class="small-box-footer">
                            More info <i class="fas fa-arrow-circle-right"></i>
                        </a>
                    </div>
                </div>
                <div class="col-lg-4 col-6">
                    <div class="small-box bg-success">
                        <div class="inner">
                            <h3><?php echo $total_policies; ?></h3>
                            <p>Security Policies</p>
                        </div>
                        <div class="icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <a href="security_policy_management.php" class="small-box-footer">
                            More info <i class="fas fa-arrow-circle-right"></i>
                        </a>
                    </div>
                </div>
                <div class="col-lg-4 col-6">
                    <div class="small-box bg-warning">
                        <div class="inner">
                            <h3><?php echo $total_violations; ?></h3>
                            <p>Policy Violations</p>
                        </div>
                        <div class="icon">
                            <i class="fas fa-exclamation-triangle"></i>
                    </div>
                        <a href="view_violations.php" class="small-box-footer">
                            More info <i class="fas fa-arrow-circle-right"></i>
                        </a>
                    </div>
                </div>
            </div>

            <!-- Recent Policy Violations -->
            <div class="row">
                <div class="col-md-12">
            <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">
                                <i class="fas fa-exclamation-triangle mr-1"></i>
                                Recent Policy Violations
                            </h3>
                            <div class="card-tools">
                                <a href="view_violations.php" class="btn btn-tool">
                                    <i class="fas fa-list"></i> View All
                                </a>
                            </div>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Username</th>
                                            <th>Policy</th>
                                            <th>Description</th>
                                            <th>Severity</th>
                                            <th class="text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($recent_violations)): ?>
                                        <tr>
                                            <td colspan="6" class="text-center">No recent violations</td>
                                        </tr>
                                        <?php else: ?>
                                            <?php foreach ($recent_violations as $violation): ?>
                                            <tr>
                                                <td><?php echo date('Y-m-d H:i', strtotime($violation['violation_date'])); ?></td>
                                                <td><?php echo htmlspecialchars($violation['username']); ?></td>
                                                <td><?php echo htmlspecialchars($violation['policy_name']); ?></td>
                                                <td><?php echo htmlspecialchars($violation['description']); ?></td>
                                                <td>
                                                    <span class="badge badge-<?php 
                                                        echo $violation['severity'] === 'high' ? 'danger' : 
                                                            ($violation['severity'] === 'medium' ? 'warning' : 'info'); 
                                                    ?>">
                                                        <?php echo ucfirst($violation['severity']); ?>
                                                    </span>
                                                </td>
                                                <td class="text-right">
                                                    <a href="delete_violation.php?id=<?php echo $violation['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure you want to delete this violation? This action cannot be undone.');">
                                                        <i class="fas fa-trash"></i> Delete
                                                    </a>
                                                </td>
                                            </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
            </div>
        </div>
    </div>

            <!-- Recent Access Logs -->
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">
                                <i class="fas fa-history mr-1"></i>
                                Recent Access Logs
                            </h3>
            </div>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recent_logs as $log): ?>
                        <tr>
                                            <td><?php echo date('Y-m-d H:i', strtotime($log['timestamp'])); ?></td>
                                            <td><?php echo htmlspecialchars($log['username'] ?? 'N/A'); ?></td>
                            <td><?php echo htmlspecialchars($log['action']); ?></td>
                                            <td>
                                                <span class="badge badge-<?php echo $log['status'] === 'success' ? 'success' : 'danger'; ?>">
                                                    <?php echo ucfirst($log['status']); ?>
                                                </span>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            </div>
        </div>
    </div>

<?php
// Include footer
include 'includes/footer.php';
?> 