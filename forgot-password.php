<?php
/*
 * Before using this page, run the following SQL once in your db_task database:
 *
 * CREATE TABLE IF NOT EXISTS password_resets (
 *     id          INT AUTO_INCREMENT PRIMARY KEY,
 *     username    VARCHAR(50) NOT NULL,
 *     token       VARCHAR(64) NOT NULL UNIQUE,
 *     expires_at  DATETIME NOT NULL,
 *     created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
 * );
 */

session_start();

// Already logged in — no need to be here
if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true) {
    header("location: welcome.php");
    exit;
}

require_once "config.php";

$username     = "";
$username_err = "";
$reset_link   = "";
$success_msg  = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Validate username field
    if (empty(trim($_POST["username"]))) {
        $username_err = "Please enter your username.";
    } else {
        $username = trim($_POST["username"]);
    }

    if (empty($username_err)) {
        // Check that the username exists in the users table
        $sql = "SELECT id FROM users WHERE username = ?";
        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows === 1) {
                // Generate a cryptographically secure token
                $token      = bin2hex(random_bytes(32)); // 64 hex chars
                $expires_at = date("Y-m-d H:i:s", strtotime("+1 hour"));

                // Remove any existing token for this user, then insert the new one
                $del = $mysqli->prepare("DELETE FROM password_resets WHERE username = ?");
                $del->bind_param("s", $username);
                $del->execute();
                $del->close();

                $ins = $mysqli->prepare(
                    "INSERT INTO password_resets (username, token, expires_at) VALUES (?, ?, ?)"
                );
                $ins->bind_param("sss", $username, $token, $expires_at);

                if ($ins->execute()) {
                    // Build the reset URL
                    $protocol   = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off") ? "https" : "http";
                    $host       = $_SERVER["HTTP_HOST"];
                    $script_dir = rtrim(dirname($_SERVER["SCRIPT_NAME"]), "/\\");
                    $reset_link = $protocol . "://" . $host . $script_dir . "/reset-password-token.php?token=" . urlencode($token);

                    $success_msg = "A reset link has been generated. In production this would be emailed to you.";
                } else {
                    $username_err = "Something went wrong. Please try again.";
                }
                $ins->close();
            } else {
                // Don't reveal whether the username exists — show the same message
                $success_msg = "If that username exists, a reset link has been generated below.";
            }
            $stmt->close();
        }
    }

    $mysqli->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forgot Password</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body { font: 14px sans-serif; }
        .wrapper { width: 400px; padding: 20px; }
    </style>
</head>
<body>
<div class="wrapper">
    <h2>Forgot Password</h2>
    <p>Enter your username and a password reset link will be generated.</p>

    <?php if (!empty($success_msg)): ?>
        <div class="alert alert-success"><?php echo htmlspecialchars($success_msg); ?></div>

        <?php if (!empty($reset_link)): ?>
            <div class="alert alert-info">
                <strong>Reset link (copy and open in browser):</strong><br>
                <a href="<?php echo htmlspecialchars($reset_link); ?>" style="word-break: break-all;">
                    <?php echo htmlspecialchars($reset_link); ?>
                </a>
                <br><small class="text-muted">This link expires in <strong>1 hour</strong>.</small>
            </div>
        <?php endif; ?>

        <p><a href="login_form.php">Back to Login</a></p>

    <?php else: ?>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username"
                       class="form-control <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>"
                       value="<?php echo htmlspecialchars($username); ?>">
                <span class="invalid-feedback"><?php echo $username_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Get Reset Link">
                <a class="btn btn-link ml-2" href="login_form.php">Back to Login</a>
            </div>
        </form>
    <?php endif; ?>
</div>
</body>
</html>
