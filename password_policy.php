<?php
class PasswordPolicy {
    private $conn;
    private $policy;

    public function __construct() {
        global $conn;
        $this->conn = $conn;
        $this->loadPolicy();
    }

    private function loadPolicy() {
        try {
            // Get the most recent password policy
            $sql = "SELECT * FROM security_policies 
                   WHERE requirements LIKE '%password_requirements%' 
                   ORDER BY created_at DESC LIMIT 1";
            $result = mysqli_query($this->conn, $sql);
            
            if ($result && mysqli_num_rows($result) > 0) {
                $row = mysqli_fetch_assoc($result);
                $this->policy = json_decode($row['requirements'], true);
            } else {
                // Default policy if none exists
                $this->policy = [
                    'password_requirements' => [
                        'min_length' => 12,
                        'require_uppercase' => true,
                        'require_lowercase' => true,
                        'require_numbers' => true,
                        'require_special_chars' => true,
                        'max_age_days' => 90,
                        'password_history' => 5,
                        'min_complexity_score' => 3
                    ],
                    'access_control' => [
                        'max_login_attempts' => 5,
                        'lockout_duration_minutes' => 30,
                        'require_mfa' => true
                    ]
                ];
            }
        } catch (Exception $e) {
            error_log("Error loading password policy: " . $e->getMessage());
            throw new Exception("Failed to load password policy");
        }
    }

    public function validatePassword($password, $username) {
        $errors = [];
        $requirements = $this->policy['password_requirements'];

        // Check minimum length
        if (strlen($password) < $requirements['min_length']) {
            $errors[] = "Password must be at least {$requirements['min_length']} characters long";
        }

        // Check for uppercase letters
        if ($requirements['require_uppercase'] && !preg_match('/[A-Z]/', $password)) {
            $errors[] = "Password must contain at least one uppercase letter";
        }

        // Check for lowercase letters
        if ($requirements['require_lowercase'] && !preg_match('/[a-z]/', $password)) {
            $errors[] = "Password must contain at least one lowercase letter";
        }

        // Check for numbers
        if ($requirements['require_numbers'] && !preg_match('/[0-9]/', $password)) {
            $errors[] = "Password must contain at least one number";
        }

        // Check for special characters
        if ($requirements['require_special_chars'] && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = "Password must contain at least one special character";
        }

        // Check password history
        if ($requirements['password_history'] > 0) {
            $sql = "SELECT password FROM password_history 
                   WHERE username = ? 
                   ORDER BY created_at DESC 
                   LIMIT ?";
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "si", $username, $requirements['password_history']);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            while ($row = mysqli_fetch_assoc($result)) {
                if (password_verify($password, $row['password'])) {
                    $errors[] = "Password cannot be the same as any of your last {$requirements['password_history']} passwords";
                    break;
                }
            }
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }

    public function logPasswordChange($username, $hashedPassword) {
        try {
            $sql = "INSERT INTO password_history (username, password) VALUES (?, ?)";
            $stmt = mysqli_prepare($this->conn, $sql);
            mysqli_stmt_bind_param($stmt, "ss", $username, $hashedPassword);
            mysqli_stmt_execute($stmt);
        } catch (Exception $e) {
            error_log("Error logging password change: " . $e->getMessage());
        }
    }

    public function getPolicyRequirements() {
        return $this->policy['password_requirements'];
    }

    public function requiresMFA() {
        return isset($this->policy['access_control']['require_mfa']) && 
               $this->policy['access_control']['require_mfa'] === true;
    }

    public function getMaxLoginAttempts() {
        return $this->policy['access_control']['max_login_attempts'] ?? 5;
    }

    public function getLockoutDuration() {
        return $this->policy['access_control']['lockout_duration_minutes'] ?? 30;
    }
}
?> 