-- Create security_policies table
CREATE TABLE IF NOT EXISTS security_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    requirements JSON,
    compliance_framework VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create security_incidents table
CREATE TABLE IF NOT EXISTS security_incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    incident_type VARCHAR(50) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    description TEXT,
    response_actions JSON,
    status ENUM('open', 'investigating', 'resolved', 'closed') DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL
);

-- Create policy_violations table
CREATE TABLE IF NOT EXISTS policy_violations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    policy_id INT,
    violation_type VARCHAR(50) NOT NULL,
    description TEXT,
    user_id INT,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    status ENUM('open', 'investigating', 'resolved', 'closed') DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (policy_id) REFERENCES security_policies(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create compliance_audit_logs table
CREATE TABLE IF NOT EXISTS compliance_audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    audit_type VARCHAR(50) NOT NULL,
    audit_results JSON,
    status ENUM('pass', 'fail', 'warning') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INT,
    FOREIGN KEY (created_by) REFERENCES users(id)
); 