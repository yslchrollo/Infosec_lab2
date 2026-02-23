<?php
// ============================================
// SECURE REGISTRATION PAGE
// Uses password_hash(), prepared statements,
// input validation, CSRF protection
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
$success = "";

if (isset($_POST['register'])) {

    // --- CSRF Validation ---
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = "Invalid request. Please try again.";
    } else {

        // --- Input Validation ---
        $username = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm  = $_POST['confirm_password'] ?? '';

        if (empty($username) || empty($email) || empty($password) || empty($confirm)) {
            $error = "Please fill in all fields.";
        } elseif (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
            $error = "Username must be 3-50 characters (letters, numbers, underscores only).";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = "Please enter a valid email address.";
        } elseif (strlen($password) < 8) {
            $error = "Password must be at least 8 characters long.";
        } elseif ($password !== $confirm) {
            $error = "Passwords do not match.";
        } else {

            // Check if username or email already exists (prepared statement)
            $check_stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
            $check_stmt->bind_param("ss", $username, $email);
            $check_stmt->execute();
            $check_result = $check_stmt->get_result();

            if ($check_result->num_rows > 0) {
                $error = "Username or email already exists.";
            } else {

                // --- FIX: Hash password with bcrypt ---
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                // --- FIX: Insert with Prepared Statement ---
                $insert_stmt = $conn->prepare("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, 'user')");
                $insert_stmt->bind_param("sss", $username, $hashed_password, $email);

                if ($insert_stmt->execute()) {
                    $success = "Registration successful! You can now login.";
                } else {
                    $error = "Registration failed. Please try again.";
                }
                $insert_stmt->close();
            }
            $check_stmt->close();
        }
    }

    // Regenerate CSRF token
    unset($_SESSION['csrf_token']);
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <link rel="stylesheet" href="style.css?v=1.1">
</head>
<body>

<div class="auth-wrapper">
    <div class="auth-card">
        <div class="auth-header">
            <h2>Create Account</h2>
            <p>Register a new account to get started</p>
        </div>
        <div class="auth-body">

            <?php if (!empty($error)): ?>
                <p class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <?php if (!empty($success)): ?>
                <p class="success"><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <form method="POST" action="register.php">
                <?php csrf_input(); ?>

                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" placeholder="Choose a username"
                           value="<?php echo htmlspecialchars($_POST['username'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           required maxlength="50">
                </div>

                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" placeholder="Enter your email"
                           value="<?php echo htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           required maxlength="100">
                </div>

                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" placeholder="Minimum 8 characters"
                           required minlength="8">
                </div>

                <div class="form-group">
                    <label>Confirm Password</label>
                    <input type="password" name="confirm_password" placeholder="Re-enter your password"
                           required minlength="8">
                </div>

                <button type="submit" name="register" class="btn-full">Create Account</button>
            </form>

            <div class="form-footer">
                Already have an account? <a href="login.php">Sign in</a>
            </div>
        </div>
    </div>
</div>

</body>
</html>
