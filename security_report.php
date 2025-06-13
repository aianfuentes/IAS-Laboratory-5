<?php
session_start();
require_once 'config.php';
require_once 'logs.php';
require_once 'rbac.php';

// Check if user is admin
if (!isset($_SESSION['user_id']) || !checkPermission($_SESSION['role'], 'admin')) {
    header('Location: index.php');
    exit();
}

$report = generateSecurityReport();

// Get detailed statistics
$sql = "SELECT 
    COUNT(CASE WHEN action = 'LOGIN' AND status = 'success' THEN 1 END) as successful_logins,
    COUNT(CASE WHEN action = 'LOGIN' AND status = 'failed' THEN 1 END) as failed_logins,
    COUNT(CASE WHEN action = 'MFA_VERIFICATION' AND status = 'success' THEN 1 END) as successful_mfa,
    COUNT(CASE WHEN action = 'MFA_VERIFICATION' AND status = 'failed' THEN 1 END) as failed_mfa
    FROM access_logs 
    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)";
$result = mysqli_query($conn, $sql);
$stats = mysqli_fetch_assoc($result);

// Get recent security events
$sql = "SELECT al.*, u.username 
        FROM access_logs al 
        LEFT JOIN users u ON al.user_id = u.id 
        WHERE al.action IN ('LOGIN', 'MFA_VERIFICATION', 'LOGOUT') 
        ORDER BY al.timestamp DESC LIMIT 20";
$result = mysqli_query($conn, $sql);
$recent_events = mysqli_fetch_all($result, MYSQLI_ASSOC);

// Get failed login attempts by IP
$sql = "SELECT ip_address, COUNT(*) as attempt_count 
        FROM access_logs 
        WHERE action = 'LOGIN' AND status = 'failed' 
        AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY ip_address 
        HAVING attempt_count > 3
        ORDER BY attempt_count DESC";
$result = mysqli_query($conn, $sql);
$suspicious_ips = mysqli_fetch_all($result, MYSQLI_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            min-height: 100vh;
            background: #f5f7fa;
            color: #2d3748;
        }

        .navbar {
            background: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .navbar-brand {
            font-size: 1.5rem;
            font-weight: 600;
            color: #4a5568;
            text-decoration: none;
        }

        .back-link {
            color: #4a5568;
            text-decoration: none;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
        }

        .back-link i {
            margin-right: 0.5rem;
        }

        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 1rem;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-top: 2rem;
        }

        .card {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        h1 {
            color: #2d3748;
            font-size: 1.8rem;
            margin-bottom: 1rem;
        }

        h2 {
            color: #4a5568;
            font-size: 1.4rem;
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #e2e8f0;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .stat-card {
            background: #f8fafc;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 0.5rem;
        }

        .stat-label {
            color: #718096;
            font-size: 0.9rem;
        }

        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 500;
        }

        .status-success {
            background: #c6f6d5;
            color: #2f855a;
        }

        .status-failed {
            background: #fed7d7;
            color: #c53030;
        }

        .alert {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }

        .alert-danger {
            background: #fed7d7;
            color: #c53030;
            border: 1px solid #f56565;
        }

        .alert-success {
            background: #c6f6d5;
            color: #2f855a;
            border: 1px solid #48bb78;
        }

        .alert-warning {
            background: #fefcbf;
            color: #975a16;
            border: 1px solid #ecc94b;
        }

        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
        }

        .modal-content {
            position: relative;
            background: white;
            margin: 5% auto;
            padding: 2rem;
            width: 90%;
            max-width: 1000px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            max-height: 80vh;
            overflow-y: auto;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #e2e8f0;
        }

        .modal-title {
            font-size: 1.5rem;
            color: #2d3748;
            font-weight: 600;
        }

        .close-modal {
            background: none;
            border: none;
            font-size: 1.5rem;
            color: #718096;
            cursor: pointer;
            padding: 0.5rem;
            transition: color 0.2s ease;
        }

        .close-modal:hover {
            color: #4a5568;
        }

        .view-events-btn {
            display: inline-flex;
            align-items: center;
            padding: 0.75rem 1.5rem;
            background: #4299e1;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.2s ease;
            text-decoration: none;
            margin-top: 1rem;
        }

        .view-events-btn:hover {
            background: #3182ce;
        }

        .view-events-btn i {
            margin-right: 0.5rem;
        }

        .table-container {
            overflow-x: auto;
            margin-top: 1rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }

        th {
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
            position: sticky;
            top: 0;
        }

        tr:hover {
            background: #f7fafc;
        }

        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .modal-content {
                margin: 10% auto;
                width: 95%;
                padding: 1rem;
            }
        }
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <nav class="navbar">
        <a href="admin_dashboard.php" class="navbar-brand">Security Report</a>
        <a href="admin_dashboard.php" class="back-link">
            <i class="fas fa-arrow-left"></i>
            Back to Dashboard
        </a>
    </nav>

    <div class="container">
        <div class="dashboard-grid">
            <div class="card">
                <h2>24-Hour Security Overview</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value"><?php echo $stats['successful_logins']; ?></div>
                        <div class="stat-label">Successful Logins</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value"><?php echo $stats['failed_logins']; ?></div>
                        <div class="stat-label">Failed Logins</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value"><?php echo $stats['successful_mfa']; ?></div>
                        <div class="stat-label">Successful MFA</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value"><?php echo $stats['failed_mfa']; ?></div>
                        <div class="stat-label">Failed MFA</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Security Status</h2>
                <?php if (detectIntrusion()): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle"></i>
                        Potential intrusion detected! Multiple failed login attempts.
                    </div>
                <?php else: ?>
                    <div class="alert alert-success">
                        <i class="fas fa-shield-alt"></i>
                        No intrusion detected. System is secure.
                    </div>
                <?php endif; ?>

                <?php if (!empty($suspicious_ips)): ?>
                    <div class="alert alert-warning">
                        <h3>Suspicious IP Addresses</h3>
                        <ul style="margin-top: 0.5rem; margin-left: 1.5rem;">
                            <?php foreach ($suspicious_ips as $ip): ?>
                                <li>
                                    <?php echo htmlspecialchars($ip['ip_address']); ?> 
                                    (<?php echo $ip['attempt_count']; ?> failed attempts)
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
            </div>

            <div class="card">
                <h2>Recent Security Events</h2>
                <p>View detailed information about recent security events and user activities.</p>
                <button class="view-events-btn" onclick="openModal()">
                    <i class="fas fa-history"></i>
                    View Recent Events
                </button>
            </div>
        </div>
    </div>

    <!-- Modal -->
    <div id="eventsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Recent Security Events</h3>
                <button class="close-modal" onclick="closeModal()">&times;</button>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>User</th>
                            <th>Action</th>
                            <th>Status</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recent_events as $event): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($event['timestamp']); ?></td>
                            <td><?php echo isset($event['username']) ? htmlspecialchars($event['username']) : 'N/A'; ?></td>
                            <td><?php echo htmlspecialchars($event['action']); ?></td>
                            <td>
                                <span class="status-badge <?php echo $event['status'] === 'success' ? 'status-success' : 'status-failed'; ?>">
                                    <?php echo htmlspecialchars($event['status']); ?>
                                </span>
                            </td>
                            <td><?php echo htmlspecialchars($event['ip_address']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        function openModal() {
            document.getElementById('eventsModal').style.display = 'block';
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            document.getElementById('eventsModal').style.display = 'none';
            document.body.style.overflow = 'auto';
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('eventsModal');
            if (event.target == modal) {
                closeModal();
            }
        }

        // Close modal with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeModal();
            }
        });
    </script>
</body>
</html> 