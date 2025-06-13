<?php
session_start();
require_once 'config.php';
require_once 'logs.php';
require_once 'vendor/autoload.php';

use RobThree\Auth\TwoFactorAuth;

if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit();
}

$tfa = new TwoFactorAuth('IAS LAB 4');

// Check if user already has MFA set up
$sql = "SELECT mfa_secret FROM users WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $_SESSION['user_id']);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user = mysqli_fetch_assoc($result);

// Only generate new secret if user doesn't have one
if (empty($user['mfa_secret'])) {
    $secret = $tfa->createSecret();
    // Store the secret in the database
    $sql = "UPDATE users SET mfa_secret = ? WHERE id = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "si", $secret, $_SESSION['user_id']);
    mysqli_stmt_execute($stmt);
} else {
    $secret = $user['mfa_secret'];
}

// Generate QR code
$qrCodeUrl = $tfa->getQRCodeImageAsDataUri('IAS LAB 4 - ' . $_SESSION['username'], $secret);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA Setup</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }

        .container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 600px;
        }

        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
            font-size: 28px;
            font-weight: 600;
        }

        .mfa-setup {
            display: flex;
            flex-direction: column;
            gap: 30px;
        }

        .step {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            border: 1px solid #e9ecef;
        }

        h2 {
            color: #444;
            margin-bottom: 15px;
            font-size: 20px;
            font-weight: 500;
        }

        p {
            color: #666;
            margin-bottom: 20px;
            line-height: 1.6;
        }

        .qr-code {
            display: flex;
            justify-content: center;
            margin: 20px 0;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }

        .qr-code img {
            max-width: 200px;
            height: auto;
        }

        form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        label {
            color: #555;
            font-size: 14px;
            font-weight: 500;
        }

        input {
            padding: 12px;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s ease;
        }

        input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        button {
            background: #667eea;
            color: white;
            padding: 12px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.3s ease;
        }

        button:hover {
            background: #764ba2;
        }

        .back-link {
            text-align: center;
            margin-top: 20px;
        }

        .back-link a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
        }

        .back-link a:hover {
            text-decoration: underline;
        }

        .instructions {
            background: #e8f4ff;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .instructions ul {
            margin-left: 20px;
            color: #555;
        }

        .instructions li {
            margin: 8px 0;
        }

        .error-message {
            background: #fee;
            color: #e33;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Multi-Factor Authentication Setup</h1>
        
        <?php if (isset($_GET['error'])): ?>
            <div class="error-message">
                <?php
                if ($_GET['error'] === 'invalid_code') {
                    echo 'Invalid verification code. Please try again.';
                }
                ?>
            </div>
        <?php endif; ?>

        <div class="mfa-setup">
            <div class="step">
                <h2>Step 1: Scan QR Code</h2>
                <div class="instructions">
                    <p>To set up MFA, follow these steps:</p>
                    <ul>
                        <li>Install Google Authenticator app on your phone</li>
                        <li>Open the app and tap the + button</li>
                        <li>Scan the QR code below</li>
                    </ul>
                </div>
                <div class="qr-code">
                    <img src="<?php echo $qrCodeUrl; ?>" alt="QR Code">
                </div>
            </div>
            
            <div class="step">
                <h2>Step 2: Verify Setup</h2>
                <p>Enter the 6-digit code shown in your authenticator app to verify the setup:</p>
                <form action="verify_mfa.php" method="post">
                    <label for="code">Authentication Code:</label>
                    <input type="text" id="code" name="code" required pattern="[0-9]{6}" 
                           placeholder="Enter 6-digit code" maxlength="6">
                    <button type="submit">Verify and Enable MFA</button>
                </form>
            </div>
        </div>

        <div class="back-link">
            <a href="logout.php">← Logout</a>
        </div>
    </div>
</body>
</html> 