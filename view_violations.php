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

// Get filter parameters
$username = isset($_GET['username']) ? $_GET['username'] : '';
$policy_name = isset($_GET['policy_name']) ? $_GET['policy_name'] : '';
$severity = isset($_GET['severity']) ? $_GET['severity'] : '';
$date_from = isset($_GET['date_from']) ? $_GET['date_from'] : '';
$date_to = isset($_GET['date_to']) ? $_GET['date_to'] : '';

// Build query
$query = "SELECT pv.*, sp.policy_name 
          FROM policy_violations pv 
          JOIN security_policies sp ON pv.policy_id = sp.id 
          WHERE 1=1";
$params = [];
$types = "";

if ($username) {
    $query .= " AND pv.username LIKE ?";
    $params[] = "%$username%";
    $types .= "s";
}

if ($policy_name) {
    $query .= " AND sp.policy_name LIKE ?";
    $params[] = "%$policy_name%";
    $types .= "s";
}

if ($severity) {
    $query .= " AND pv.severity = ?";
    $params[] = $severity;
    $types .= "s";
}

if ($date_from) {
    $query .= " AND pv.violation_date >= ?";
    $params[] = $date_from;
    $types .= "s";
}

if ($date_to) {
    $query .= " AND pv.violation_date <= ?";
    $params[] = $date_to;
    $types .= "s";
}

$query .= " ORDER BY pv.violation_date DESC";

$stmt = $conn->prepare($query);
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$violations = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

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
                    <h1 class="m-0">Policy Violations</h1>
                </div>
            </div>
        </div>
    </div>

    <!-- Main content -->
    <div class="content">
        <div class="container-fluid">
            <!-- Filter Card -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Filter Violations</h3>
                </div>
                <div class="card-body">
                    <form method="GET" class="row">
                        <div class="col-md-3">
                            <div class="form-group">
                                <label for="username">Username</label>
                                <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($username); ?>">
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="form-group">
                                <label for="policy_name">Policy Name</label>
                                <input type="text" class="form-control" id="policy_name" name="policy_name" value="<?php echo htmlspecialchars($policy_name); ?>">
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="form-group">
                                <label for="severity">Severity</label>
                                <select class="form-control" id="severity" name="severity">
                                    <option value="">All</option>
                                    <option value="low" <?php echo $severity === 'low' ? 'selected' : ''; ?>>Low</option>
                                    <option value="medium" <?php echo $severity === 'medium' ? 'selected' : ''; ?>>Medium</option>
                                    <option value="high" <?php echo $severity === 'high' ? 'selected' : ''; ?>>High</option>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="form-group">
                                <label for="date_from">Date From</label>
                                <input type="date" class="form-control" id="date_from" name="date_from" value="<?php echo htmlspecialchars($date_from); ?>">
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="form-group">
                                <label for="date_to">Date To</label>
                                <input type="date" class="form-control" id="date_to" name="date_to" value="<?php echo htmlspecialchars($date_to); ?>">
                            </div>
                        </div>
                        <div class="col-12">
                            <button type="submit" class="btn btn-primary">Apply Filters</button>
                            <a href="view_violations.php" class="btn btn-secondary">Clear Filters</a>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Violations Table Card -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Policy Violations</h3>
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
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($violations as $violation): ?>
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
                                    <td>
                                        <span class="badge badge-<?php echo $violation['status'] === 'open' ? 'danger' : 'success'; ?>">
                                            <?php echo ucfirst($violation['status']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <a href="update_violation.php?id=<?php echo $violation['id']; ?>" class="btn btn-sm btn-info">
                                            <i class="fas fa-edit"></i> Update
                                        </a>
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

<?php
// Include footer
include 'includes/footer.php';
?> 