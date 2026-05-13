<?php
session_start();

// Already logged in — no need to be here
if (isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true) {
    header("location: welcome.php");
    exit;
}

require_once "config.php";

$new_password      = $confirm_password      = "";
$new_password_err  = $confirm_password_err  = "";
$token_err         = "";
$token             = "";

// Read and validate the token from the URL
if (isset($_GET["token"]) && !empty(trim($_GET["token"]))) {
    $token = trim($_GET["token"]);
} else {
    $token_err = "No reset token provided. Please use the link from your reset request.";
}

// Look up the token in the database (only if we have one)
$username = "";
if (empty($token_err)) {
    $sql = "SELECT username, expires_at FROM password_resets WHERE token = ?";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 1) {
            $stmt->bind_result($db_username, $expires_at);
            $stmt->fetch();

            // Check expiry
            if (strtotime($expires_at) < time()) {
                $token_err = "This reset link has expired. Please request a new one.";
            } else {
                $username = $db_username;
            }
        } else {
            $token_err = "Invalid reset token. Please request a new one.";
        }
        $stmt->close();
    }
}

// Process the new-password form
if ($_SERVER["REQUEST_METHOD"] == "POST" && empty($token_err)) {

    // Re-read token from the hidden field on POST
    $token = trim($_POST["token"] ?? "");

    // Validate new password
    if (empty(trim($_POST["new_password"]))) {
        $new_password_err = "Please enter the new password.";
    } elseif (strlen(trim($_POST["new_password"])) < 6) {
        $new_password_err = "Password must have at least 6 characters.";
    } else {
        $new_password = trim($_POST["new_password"]);
    }

    // Validate confirm password
    if (empty(trim($_POST["confirm_password"]))) {
        $confirm_password_err = "Please confirm the password.";
    } else {
        $confirm_password = trim($_POST["confirm_password"]);
        if (empty($new_password_err) && ($new_password !== $confirm_password)) {
            $confirm_password_err = "Passwords do not match.";
        }
    }

    if (empty($new_password_err) && empty($confirm_password_err)) {
        // Re-validate the token against the DB before actually updating
        $sql = "SELECT username FROM password_resets WHERE token = ? AND expires_at > NOW()";
        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("s", $token);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows === 1) {
                $stmt->bind_result($username);
                $stmt->fetch();
                $stmt->close();

                // Update the password
                $upd = $mysqli->prepare("UPDATE users SET password = ? WHERE username = ?");
                $upd->bind_param("ss", $param_password, $username);
                $param_password = password_hash($new_password, PASSWORD_DEFAULT);

                if ($upd->execute()) {
                    // Delete the used token
                    $del = $mysqli->prepare("DELETE FROM password_resets WHERE token = ?");
                    $del->bind_param("s", $token);
                    $del->execute();
                    $del->close();

                    $upd->close();
                    $mysqli->close();

                    // Redirect to login with a success flag
                    header("location: login_form.php?reset=1");
                    exit;
                } else {
                    $new_password_err = "Something went wrong. Please try again.";
                }
                $upd->close();
            } else {
                $token_err = "Reset link is invalid or has expired.";
            }
        }
    }

    $mysqli->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reset Password</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body { font: 14px sans-serif; }
        .wrapper { width: 400px; padding: 20px; }
    </style>
</head>
<body>
<div class="wrapper">
    <h2>Reset Password</h2>

    <?php if (!empty($token_err)): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($token_err); ?></div>
        <p><a href="forgot-password.php">Request a new reset link</a></p>

    <?php else: ?>
        <p>Enter a new password for <strong><?php echo htmlspecialchars($username); ?></strong>.</p>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <!-- Pass the token through the form -->
            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">

            <div class="form-group">
                <label>New Password</label>
                <input type="password" name="new_password"
                       class="form-control <?php echo (!empty($new_password_err)) ? 'is-invalid' : ''; ?>">
                <span class="invalid-feedback"><?php echo $new_password_err; ?></span>
            </div>
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password"
                       class="form-control <?php echo (!empty($confirm_password_err)) ? 'is-invalid' : ''; ?>">
                <span class="invalid-feedback"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Reset Password">
                <a class="btn btn-link ml-2" href="login_form.php">Cancel</a>
            </div>
        </form>
    <?php endif; ?>
</div>
</body>
</html>
