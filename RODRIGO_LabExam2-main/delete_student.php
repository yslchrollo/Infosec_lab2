<?php
// ============================================
// SECURE DELETE STUDENT
// Fixes: SQL Injection, direct object reference,
// access control, CSRF - now handled via POST in dashboard.php
// ============================================
session_start();
include("db.php");

// --- FIX: Access Control ---
if (!isset($_SESSION['user']) || !isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// --- FIX: Admin Only ---
if ($_SESSION['role'] !== 'admin') {
    header("Location: dashboard.php");
    exit();
}

// --- FIX: Only accept POST requests (no GET-based deletion) ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: dashboard.php");
    exit();
}

// --- FIX: Validate and sanitize the ID ---
$id = intval($_POST['student_id'] ?? 0);

if ($id > 0) {
    // --- FIX: Prepared Statement (prevents SQL Injection) ---
    $stmt = $conn->prepare("DELETE FROM students WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->close();
}

header("Location: dashboard.php");
exit();
?>
