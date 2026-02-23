<?php
// ============================================
// SECURE LOGIN PAGE
// Fixes: SQL Injection, plaintext passwords,
// session fixation, XSS, CSRF, input validation
// ============================================

// Secure session cookie settings (MUST be before session_start)
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);

session_start();

include("db.php");
include("csrf.php");

// Redirect if already logged in
if (isset($_SESSION['user'])) {
    header("Location: dashboard.php");
    exit();
}

$error = "";

if (isset($_POST['login'])) {

    // --- CSRF Validation ---
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = "Invalid request. Please try again.";
    } else {

        // --- Input Validation ---
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($username) || empty($password)) {
            $error = "Please fill in all fields.";
        } elseif (strlen($username) > 50) {
            $error = "Username is too long.";
        } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            $error = "Username contains invalid characters.";
        } else {

            // --- FIX: Prepared Statement (prevents SQL Injection) ---
            $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows === 1) {
                $user = $result->fetch_assoc();

                // --- FIX: Password Verification using password_verify() ---
                if (password_verify($password, $user['password'])) {

                    // --- FIX: Regenerate session ID to prevent session fixation ---
                    session_regenerate_id(true);

                    $_SESSION['user'] = $user['username'];
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['role'] = $user['role'];
                    $_SESSION['last_activity'] = time();

                    // Log successful login
                    $log_stmt = $conn->prepare("INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, 1)");
                    $ip = $_SERVER['REMOTE_ADDR'];
                    $log_stmt->bind_param("ss", $username, $ip);
                    $log_stmt->execute();
                    $log_stmt->close();

                    header("Location: dashboard.php");
                    exit(); // FIX: exit() after redirect
                } else {
                    $error = "Invalid username or password.";
                }
            } else {
                $error = "Invalid username or password.";
            }

            // Log failed attempt
            if (!empty($error)) {
                $log_stmt = $conn->prepare("INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, 0)");
                $ip = $_SERVER['REMOTE_ADDR'];
                $log_stmt->bind_param("ss", $username, $ip);
                $log_stmt->execute();
                $log_stmt->close();
            }

            $stmt->close();
        }
    }

    // Regenerate CSRF token after each attempt
    unset($_SESSION['csrf_token']);
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link rel="stylesheet" href="style.css?v=1.1">
</head>
<body>

<div class="auth-wrapper">
    <div class="auth-card">
        <div class="auth-header">
            <h2>Admin Login</h2>
            <p>Sign in to manage your students</p>
        </div>
        <div class="auth-body">

            <?php if (!empty($error)): ?>
                <p class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <form method="POST" action="login.php">
                <?php csrf_input(); ?>

                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" placeholder="Enter your username"
                           value="<?php echo htmlspecialchars($_POST['username'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           required maxlength="50">
                </div>

                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" placeholder="Enter your password"
                           required maxlength="255">
                </div>

                <button type="submit" name="login" class="btn-full">Sign In</button>
            </form>

            <div class="form-footer">
                Don't have an account? <a href="register.php">Register here</a>
            </div>
        </div>
    </div>
</div>

</body>
</html>
