<?php
// ============================================
// SECURE DATABASE CONNECTION
// Uses OOP mysqli with charset + error handling
// ============================================

define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'infosec_lab');

// Create connection using OOP style (needed for prepared statements)
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

// Check connection - don't expose details to user
if ($conn->connect_error) {
    error_log("Database connection failed: " . $conn->connect_error);
    die("Connection failed. Please try again later.");
}

// Set charset to prevent encoding-based attacks
$conn->set_charset("utf8mb4");
?>
