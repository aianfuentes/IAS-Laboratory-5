<?php
// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'config.php';
require_once 'security_policies.php';
require_once 'auth.php';

// Check if session is not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Database connection
try {
    $db = new PDO("mysql:host=localhost;dbname=iaslab5", "root", "");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Check if user is authenticated and has admin privileges
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header('Location: login.php');
    exit();
}

$securityPolicies = new SecurityPolicies($db);
$message = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'create_policy':
                try {
                    // Debug output
                    error_log("Received policy creation request");
                    error_log("POST data: " . print_r($_POST, true));
                    
                    $name = $_POST['name'] ?? '';
                    $description = $_POST['description'] ?? '';
                    $requirements = $_POST['requirements'] ?? '';
                    $complianceFramework = $_POST['compliance_framework'] ?? '';

                    // Validate inputs
                    if (empty($name)) {
                        throw new Exception("Policy name is required");
                    }

                    // Validate JSON
                    if (!empty($requirements)) {
                        $decoded = json_decode($requirements, true);
                        if (json_last_error() !== JSON_ERROR_NONE) {
                            throw new Exception("Invalid JSON in requirements: " . json_last_error_msg());
                        }
                        // Re-encode to ensure proper formatting
                        $requirements = json_encode($decoded, JSON_PRETTY_PRINT);
                    }

                    // Debug output
                    error_log("Processed policy data:");
                    error_log("Name: " . $name);
                    error_log("Description: " . $description);
                    error_log("Requirements: " . $requirements);
                    error_log("Compliance Framework: " . $complianceFramework);

                    $result = $securityPolicies->defineSecurityPolicy($name, $description, $requirements, $complianceFramework);
                    
                    if ($result) {
                        $message = "Security policy created successfully!";
                        error_log("Policy created successfully");
                    } else {
                        $message = "Failed to create security policy.";
                        error_log("Failed to create policy");
                    }
                } catch (Exception $e) {
                    $message = "Error: " . $e->getMessage();
                    error_log("Error creating policy: " . $e->getMessage());
                }
                break;

            case 'run_audit':
                $auditResults = $securityPolicies->conductComplianceAudit();
                $_SESSION['audit_results'] = $auditResults;
                break;
        }
    }
}

// Get existing policies
try {
    $policies = $securityPolicies->getAllPolicies();
    error_log("Retrieved " . count($policies) . " policies");
    error_log("Policies: " . print_r($policies, true));
} catch (Exception $e) {
    error_log("Error retrieving policies: " . $e->getMessage());
    $policies = [];
}

// Get recent incidents
try {
    $incidents = $securityPolicies->getRecentIncidents();
} catch (Exception $e) {
    error_log("Error retrieving incidents: " . $e->getMessage());
    $incidents = [];
}

// Get recent violations
try {
    $violations = $securityPolicies->getRecentViolations();
} catch (Exception $e) {
    error_log("Error retrieving violations: " . $e->getMessage());
    $violations = [];
}

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
                    <h1 class="m-0">Security Policy Management</h1>
                </div>
            </div>
        </div>
    </div>

    <!-- Main content -->
    <div class="content">
        <div class="container-fluid">
            <!-- Create New Policy Card -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Create New Security Policy</h3>
                </div>
                <div class="card-body">
                    <form method="POST" action="create_policy.php">
                        <div class="form-group">
                            <label for="policy_name">Policy Name</label>
                            <input type="text" class="form-control" id="policy_name" name="policy_name" required>
                        </div>
                        <div class="form-group">
                            <label for="description">Description</label>
                            <textarea class="form-control" id="description" name="description" rows="3" required></textarea>
                        </div>
                        <div class="form-group">
                            <label for="requirements">Requirements (JSON)</label>
                            <textarea class="form-control" id="requirements" name="requirements" rows="5" required></textarea>
                            <small class="form-text text-muted">Enter policy requirements in JSON format</small>
                        </div>
                        <button type="submit" class="btn btn-primary">Create Policy</button>
                    </form>
                </div>
            </div>

            <!-- Existing Policies -->
            <div class="row">
                <div class="col-md-12">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">
                                <i class="fas fa-shield-alt mr-1"></i>
                                Existing Security Policies
                            </h3>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>Name</th>
                                            <th>Description</th>
                                            <th>Requirements</th>
                                            <th>Created At</th>
                                            <th class="text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($policies)): ?>
                                        <tr>
                                            <td colspan="5" class="text-center">No policies found</td>
                                        </tr>
                                        <?php else: ?>
                                            <?php foreach ($policies as $policy): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($policy['name'] ?? 'Unnamed Policy'); ?></td>
                                                <td><?php echo htmlspecialchars($policy['description'] ?? ''); ?></td>
                                                <td>
                                                    <?php 
                                                    $requirements = json_decode($policy['requirements'], true);
                                                    if ($requirements) {
                                                        echo '<ul class="list-unstyled mb-0">';
                                                        if (isset($requirements['password_requirements'])) {
                                                            $pw = $requirements['password_requirements'];
                                                            echo '<li><strong>Password:</strong> ';
                                                            echo 'Min length: ' . ($pw['min_length'] ?? 'N/A') . ', ';
                                                            echo 'Max age: ' . ($pw['max_age_days'] ?? 'N/A') . ' days';
                                                            echo '</li>';
                                                        }
                                                        if (isset($requirements['access_control'])) {
                                                            $ac = $requirements['access_control'];
                                                            echo '<li><strong>Access:</strong> ';
                                                            echo 'Max attempts: ' . ($ac['max_login_attempts'] ?? 'N/A') . ', ';
                                                            echo 'Lockout: ' . ($ac['lockout_duration_minutes'] ?? 'N/A') . ' min';
                                                            echo '</li>';
                                                        }
                                                        echo '</ul>';
                                                    }
                                                    ?>
                                                </td>
                                                <td><?php echo date('Y-m-d H:i', strtotime($policy['created_at'])); ?></td>
                                                <td class="text-right">
                                                    <a href="delete_policy.php?id=<?php echo $policy['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure you want to delete this policy? This action cannot be undone.');">
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
        </div>
    </div>
</div>

<?php
// Include footer
include 'includes/footer.php';
?> 