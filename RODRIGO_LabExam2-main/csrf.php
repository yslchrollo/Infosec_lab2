<?php
// ============================================
// CSRF TOKEN GENERATION AND VALIDATION
// Prevents Cross-Site Request Forgery attacks
// ============================================

/**
 * Generate a CSRF token and store it in the session
 */
function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Output a hidden CSRF input field for forms
 */
function csrf_input() {
    $token = generate_csrf_token();
    echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
}

/**
 * Validate the CSRF token from a submitted form
 */
function validate_csrf_token($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}
?>
