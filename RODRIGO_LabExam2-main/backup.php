<?php
// ============================================
// DATABASE BACKUP STRATEGY
// Admin-only page for manual backup +
// documentation of backup procedures
// ============================================

// Secure session cookie settings (MUST be before session_start)
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);

session_start();

include("db.php");

// --- Access Control: Admin Only ---
if (!isset($_SESSION['user']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header("Location: login.php");
    exit();
}

// Session Timeout
$timeout = 1800;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout) {
    session_unset();
    session_destroy();
    header("Location: login.php?timeout=1");
    exit();
}
$_SESSION['last_activity'] = time();

$message = "";

// Manual backup trigger
if (isset($_POST['create_backup'])) {

    $backup_dir = dirname(__DIR__) . '/backups/';

    // Create backup directory outside web root if it doesn't exist
    if (!is_dir($backup_dir)) {
        mkdir($backup_dir, 0750, true);
    }

    $filename = $backup_dir . 'backup_' . date('Y-m-d_H-i-s') . '.sql';

    // Using mysqldump
    $command = sprintf(
        '"%s" --host=%s --user=%s --password=%s %s > %s 2>&1',
        'C:\\xampp\\mysql\\bin\\mysqldump.exe',
        escapeshellarg(DB_HOST),
        escapeshellarg(DB_USER),
        escapeshellarg(DB_PASS),
        escapeshellarg(DB_NAME),
        escapeshellarg($filename)
    );

    exec($command, $output, $return_var);

    if ($return_var === 0 && file_exists($filename)) {
        $message = "Backup created successfully: " . basename($filename);
    } else {
        $message = "Backup failed. Error: " . implode("\n", $output);
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Backup Management</title>
    <link rel="stylesheet" href="style.css?v=1.1">
</head>
<body>

<div class="backup-wrapper">
    <div class="backup-card">
        <div class="backup-header">
            <h2>Database Backup</h2>
            <a href="dashboard.php">Back to Dashboard</a>
        </div>
        <div class="backup-body">

            <?php if (!empty($message)): ?>
                <p class="success"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <h3>Backup Strategy</h3>
            <table>
                <tr>
                    <th>Strategy</th>
                    <th>Details</th>
                </tr>
                <tr>
                    <td><strong>Daily Automated Backups</strong></td>
                    <td>Scheduled at 2:00 AM via Windows Task Scheduler using mysqldump</td>
                </tr>
                <tr>
                    <td><strong>Retention Policy</strong></td>
                    <td>7 daily backups, 4 weekly backups, 12 monthly backups</td>
                </tr>
                <tr>
                    <td><strong>Storage Location</strong></td>
                    <td>Outside web root (C:\backups\) + offsite/cloud copy</td>
                </tr>
                <tr>
                    <td><strong>Recovery Testing</strong></td>
                    <td>Monthly restore tests to verify backup integrity</td>
                </tr>
                <tr>
                    <td><strong>Recovery Command</strong></td>
                    <td><code>mysql -u root infosec_lab &lt; backup_file.sql</code></td>
                </tr>
            </table>

            <h3>Windows Task Scheduler Command</h3>
            <p><code>C:\xampp\mysql\bin\mysqldump.exe --user=root infosec_lab &gt; C:\backups\backup_%date:~-4%-%date:~4,2%-%date:~7,2%.sql</code></p>

            <form method="POST" style="margin-top: 24px;">
                <button type="submit" name="create_backup" class="btn-full"
                        onclick="return confirm('Create a database backup now?');">
                    Create Backup Now
                </button>
            </form>

            <?php
            // List existing backups
            $backup_dir = dirname(__DIR__) . '/backups/';
            if (is_dir($backup_dir)) {
                $files = glob($backup_dir . 'backup_*.sql');
                if (!empty($files)):
                    rsort($files);
            ?>
            <h3>Existing Backups</h3>
            <ul>
                <?php foreach ($files as $file): ?>
                    <li><?php echo htmlspecialchars(basename($file), ENT_QUOTES, 'UTF-8'); ?>
                        (<?php echo round(filesize($file) / 1024, 2); ?> KB)
                    </li>
                <?php endforeach; ?>
            </ul>
            <?php
                endif;
            }
            ?>
        </div>
    </div>
</div>

</body>
</html>
