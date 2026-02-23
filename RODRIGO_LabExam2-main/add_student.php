<?php
// ============================================
// SECURE ADD STUDENT PAGE
// Fixes: SQL Injection, access control, CSRF,
// input validation, output escaping
// ============================================

// Secure session cookie settings (MUST be before session_start)
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);

session_start();

include("db.php");
include("csrf.php");

// --- FIX: Access Control ---
if (!isset($_SESSION['user']) || !isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// --- Session Timeout ---
$timeout = 1800;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout) {
    session_unset();
    session_destroy();
    header("Location: login.php?timeout=1");
    exit();
}
$_SESSION['last_activity'] = time();

$error = "";
$success = "";

// Fetch courses for dropdown (normalized - from courses table)
$courses_result = $conn->query("SELECT id, course_code, course_description FROM courses ORDER BY course_code");
$courses = [];
while ($cat = $courses_result->fetch_assoc()) {
    $courses[] = $cat;
}

if (isset($_POST['add'])) {

    // --- CSRF Validation ---
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = "Invalid request. Please try again.";
    } else {

        // --- Input Validation ---
        $student_id = trim($_POST['student_id'] ?? '');
        $fullname   = trim($_POST['fullname'] ?? '');
        $email      = trim($_POST['email'] ?? '');
        $course_id  = intval($_POST['course_id'] ?? 0);

        if (empty($student_id) || empty($fullname) || empty($email)) {
            $error = "Please fill in all required fields.";
        } elseif (strlen($student_id) > 50) {
            $error = "Student ID is too long (max 50 characters).";
        } elseif (strlen($fullname) > 100) {
            $error = "Full name is too long (max 100 characters).";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = "Please enter a valid email address.";
        } elseif ($course_id <= 0) {
            $error = "Please select a course.";
        } else {

            // Check if student_id already exists
            $check_stmt = $conn->prepare("SELECT id FROM students WHERE student_id = ?");
            $check_stmt->bind_param("s", $student_id);
            $check_stmt->execute();
            if ($check_stmt->get_result()->num_rows > 0) {
                $error = "Student ID already exists.";
            } else {

                // --- FIX: Prepared Statement (prevents SQL Injection) ---
                $stmt = $conn->prepare("INSERT INTO students (student_id, fullname, email, course_id, created_by) VALUES (?, ?, ?, ?, ?)");
                $created_by = $_SESSION['user_id'];
                $stmt->bind_param("sssii", $student_id, $fullname, $email, $course_id, $created_by);

                if ($stmt->execute()) {
                    $success = "Student added successfully!";
                    header("Location: dashboard.php");
                    exit();
                } else {
                    $error = "Failed to add student. Please try again.";
                }
                $stmt->close();
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
    <title>Add Student</title>
    <link rel="stylesheet" href="style.css?v=1.1">
</head>
<body>

<div class="form-wrapper">
    <div class="form-card">
        <div class="form-header">
            <h2>Add Student</h2>
            <a href="dashboard.php">Back to Dashboard</a>
        </div>
        <div class="form-body">

            <?php if (!empty($error)): ?>
                <p class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <?php if (!empty($success)): ?>
                <p class="success"><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <form method="POST" action="add_student.php">
                <?php csrf_input(); ?>

                <div class="form-group">
                    <label>Student ID</label>
                    <input type="text" name="student_id" placeholder="e.g., 2024-0001"
                           value="<?php echo htmlspecialchars($_POST['student_id'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           required maxlength="50">
                </div>

                <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" name="fullname" placeholder="Enter full name"
                           value="<?php echo htmlspecialchars($_POST['fullname'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           required maxlength="100">
                </div>

                <div class="form-group">
                    <label>Email Address</label>
                    <input type="email" name="email" placeholder="Enter email address"
                           value="<?php echo htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           required maxlength="100">
                </div>

                <div class="form-group">
                    <label>Course</label>
                    <select name="course_id" required>
                        <option value="">-- Select Course --</option>
                        <?php foreach ($courses as $course): ?>
                            <option value="<?php echo intval($course['id']); ?>"
                                <?php echo (intval($_POST['course_id'] ?? 0) === intval($course['id'])) ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($course['course_code'] . ' - ' . $course['course_description'], ENT_QUOTES, 'UTF-8'); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <button type="submit" name="add" class="btn-full">Add Student</button>
            </form>
        </div>
    </div>
</div>

</body>
</html>
