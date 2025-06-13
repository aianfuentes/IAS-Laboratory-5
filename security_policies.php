<?php
require_once 'config.php';
require_once 'vendor/autoload.php';

use Firebase\JWT\JWT;

class SecurityPolicies {
    private $pdo;
    private $logger;

    public function __construct() {
        try {
            $this->pdo = new PDO("mysql:host=localhost;dbname=iaslab5", "root", "");
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->logger = new Logger();
        } catch (PDOException $e) {
            error_log("Database connection error: " . $e->getMessage());
            throw new Exception("Database connection failed");
        }
    }

    // Security Policy Management
    public function defineSecurityPolicy($name, $description, $requirements, $complianceFramework) {
        try {
            // Validate inputs
            if (empty($name)) {
                throw new Exception("Policy name is required");
            }

            // Validate JSON if provided
            if (!empty($requirements)) {
                $decoded = json_decode($requirements, true);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new Exception("Invalid JSON in requirements: " . json_last_error_msg());
                }
                // Re-encode to ensure proper formatting
                $requirements = json_encode($decoded, JSON_PRETTY_PRINT);
            }

            // Log the attempt
            $this->logger->log("Attempting to create security policy: " . $name);

            // Prepare and execute the query
            $sql = "INSERT INTO security_policies (name, description, requirements, compliance_framework) 
                    VALUES (?, ?, ?, ?)";
            $stmt = $this->pdo->prepare($sql);
            
            $result = $stmt->execute([
                $name,
                $description,
                $requirements,
                $complianceFramework
            ]);

            if ($result) {
                $this->logger->log("Successfully created security policy: " . $name);
                return true;
            } else {
                $this->logger->log("Failed to create security policy: " . $name);
                return false;
            }
        } catch (Exception $e) {
            $this->logger->log("Error creating security policy: " . $e->getMessage());
            throw $e;
        }
    }

    public function getAllPolicies() {
        try {
            $stmt = $this->pdo->query("SELECT * FROM security_policies ORDER BY created_at DESC");
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->logger->log("Error retrieving policies: " . $e->getMessage());
            throw new Exception("Failed to retrieve policies");
        }
    }

    public function getRecentIncidents() {
        try {
            $stmt = $this->pdo->query("SELECT * FROM security_incidents ORDER BY reported_at DESC LIMIT 5");
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->logger->log("Error retrieving incidents: " . $e->getMessage());
            throw new Exception("Failed to retrieve incidents");
        }
    }

    public function getRecentViolations() {
        try {
            $stmt = $this->pdo->query("SELECT * FROM policy_violations ORDER BY violated_at DESC LIMIT 5");
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->logger->log("Error retrieving violations: " . $e->getMessage());
            throw new Exception("Failed to retrieve violations");
        }
    }

    // Password Policy Implementation
    public function enforcePasswordPolicy($password) {
        $requirements = [
            'min_length' => 12,
            'require_uppercase' => true,
            'require_lowercase' => true,
            'require_numbers' => true,
            'require_special_chars' => true
        ];

        $errors = [];
        if (strlen($password) < $requirements['min_length']) {
            $errors[] = "Password must be at least {$requirements['min_length']} characters long";
        }
        if ($requirements['require_uppercase'] && !preg_match('/[A-Z]/', $password)) {
            $errors[] = "Password must contain at least one uppercase letter";
        }
        if ($requirements['require_lowercase'] && !preg_match('/[a-z]/', $password)) {
            $errors[] = "Password must contain at least one lowercase letter";
        }
        if ($requirements['require_numbers'] && !preg_match('/[0-9]/', $password)) {
            $errors[] = "Password must contain at least one number";
        }
        if ($requirements['require_special_chars'] && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = "Password must contain at least one special character";
        }

        return $errors;
    }

    // Access Control Policy
    public function enforceAccessControl($user, $resource) {
        // Implement least privilege principle
        $requiredRole = $this->getRequiredRoleForResource($resource);
        return $this->checkUserRole($user, $requiredRole);
    }

    // Security Compliance Audit
    public function conductComplianceAudit() {
        $auditResults = [
            'password_policies' => $this->auditPasswordPolicies(),
            'access_controls' => $this->auditAccessControls(),
            'data_protection' => $this->auditDataProtection(),
            'security_incidents' => $this->auditSecurityIncidents()
        ];

        $this->logger->info('Compliance audit completed', $auditResults);
        return $auditResults;
    }

    // Security Incident Response
    public function handleSecurityIncident($incident) {
        $response = [
            'timestamp' => date('Y-m-d H:i:s'),
            'incident_type' => $incident['type'],
            'severity' => $incident['severity'],
            'response_actions' => []
        ];

        // Log the incident
        $this->logger->error('Security incident detected', $incident);

        // Implement automated response based on incident type
        switch ($incident['type']) {
            case 'unauthorized_access':
                $response['response_actions'][] = $this->handleUnauthorizedAccess($incident);
                break;
            case 'data_breach':
                $response['response_actions'][] = $this->handleDataBreach($incident);
                break;
            case 'suspicious_activity':
                $response['response_actions'][] = $this->handleSuspiciousActivity($incident);
                break;
        }

        return $response;
    }

    // Policy Violation Detection
    public function detectPolicyViolations() {
        $violations = [];
        
        // Check for password policy violations
        $violations['password'] = $this->checkPasswordViolations();
        
        // Check for access control violations
        $violations['access'] = $this->checkAccessViolations();
        
        // Check for data protection violations
        $violations['data'] = $this->checkDataProtectionViolations();

        return $violations;
    }

    // Helper methods
    private function auditPasswordPolicies() {
        // Implement password policy audit logic
        return ['status' => 'compliant', 'details' => []];
    }

    private function auditAccessControls() {
        // Implement access control audit logic
        return ['status' => 'compliant', 'details' => []];
    }

    private function auditDataProtection() {
        // Implement data protection audit logic
        return ['status' => 'compliant', 'details' => []];
    }

    private function auditSecurityIncidents() {
        // Implement security incident audit logic
        return ['status' => 'compliant', 'details' => []];
    }

    private function handleUnauthorizedAccess($incident) {
        // Implement unauthorized access response
        return ['action' => 'block_ip', 'details' => []];
    }

    private function handleDataBreach($incident) {
        // Implement data breach response
        return ['action' => 'isolate_system', 'details' => []];
    }

    private function handleSuspiciousActivity($incident) {
        // Implement suspicious activity response
        return ['action' => 'increase_monitoring', 'details' => []];
    }

    private function checkPasswordViolations() {
        // Implement password violation checks
        return [];
    }

    private function checkAccessViolations() {
        // Implement access violation checks
        return [];
    }

    private function checkDataProtectionViolations() {
        // Implement data protection violation checks
        return [];
    }
}

// Logger class for security events
class Logger {
    private $logFile;

    public function __construct() {
        $this->logFile = __DIR__ . '/logs/security.log';
        $this->ensureLogDirectoryExists();
    }

    private function ensureLogDirectoryExists() {
        $logDir = dirname($this->logFile);
        if (!file_exists($logDir)) {
            mkdir($logDir, 0777, true);
        }
    }

    public function log($message) {
        $timestamp = date('Y-m-d H:i:s');
        $logMessage = "[$timestamp] $message" . PHP_EOL;
        file_put_contents($this->logFile, $logMessage, FILE_APPEND);
    }
}
?> 