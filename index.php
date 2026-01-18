<?php
session_start();

// Database Configuration connect

$host = "localhost";
$username = "root";
$password = "";
$database = "goal_tracker_app";

// Create connection db

$conn = new mysqli($host, $username, $password);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Create database if not exists in database
$conn->query("CREATE DATABASE IF NOT EXISTS $database");
$conn->select_db($database);

// Create tables in database

$conn->query("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    reset_token VARCHAR(255),
    reset_expires DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
)");

$conn->query("CREATE TABLE IF NOT EXISTS goals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    deadline DATE,
    status ENUM('pending', 'completed') DEFAULT 'pending',
    is_hidden BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)");

// Helper Functions
function sendEmail($to, $subject, $message) {
    $headers = "From: noreply@goaltracker.com\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    return mail($to, $subject, $message, $headers);
}

function generateToken() {
    return bin2hex(random_bytes(32));
}

function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: ?action=login");
        exit();
    }
}

function logout() {
    session_destroy();
    header("Location: ?action=login");
    exit();
}

// Auto logout after 30 minutes of inactivity
if (isLoggedIn() && isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 1800)) {
    logout();
}
if (isLoggedIn()) {
    $_SESSION['last_activity'] = time();
}

// Get action from URL
$action = $_GET['action'] ?? 'dashboard';

// Route handling
switch($action) {
    case 'register':
        handleRegister($conn);
        break;
    case 'login':
        handleLogin($conn);
        break;
    case 'logout':
        logout();
        break;
    case 'verify':
        handleVerification($conn);
        break;
    case 'forgot':
        handleForgotPassword($conn);
        break;
    case 'reset':
        handleResetPassword($conn);
        break;
    case 'add_goal':
        requireLogin();
        handleAddGoal($conn);
        break;
    case 'edit_goal':
        requireLogin();
        handleEditGoal($conn);
        break;
    case 'delete_goal':
        requireLogin();
        handleDeleteGoal($conn);
        break;
    case 'complete_goal':
        requireLogin();
        handleCompleteGoal($conn);
        break;
    case 'hidden_goals':
        requireLogin();
        showHiddenGoals($conn);
        break;
    case 'verify_hidden':
        requireLogin();
        handleHiddenVerification($conn);
        break;
    case 'dashboard':
    default:
        if (isLoggedIn()) {
            showDashboard($conn);
        } else {
            handleLogin($conn);
        }
        break;
}

// Handler Functions
function handleRegister($conn) {
    $error = '';
    $success = '';
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
        $password = trim($_POST['password']);
        $confirm_password = trim($_POST['confirm_password']);
        
        if (!$email) {
            $error = "Invalid email address";
        } elseif (strlen($password) < 6) {
            $error = "Password must be at least 6 characters";
        } elseif ($password !== $confirm_password) {
            $error = "Passwords do not match";
        } else {
            $check = $conn->query("SELECT id FROM users WHERE email = '" . $conn->real_escape_string($email) . "'");
            if ($check->num_rows > 0) {
                $error = "Email already registered";
            } else {
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $verification_token = generateToken();
                
                $stmt = $conn->prepare("INSERT INTO users (email, password, verification_token) VALUES (?, ?, ?)");
                $stmt->bind_param("sss", $email, $hashed_password, $verification_token);
                
                if ($stmt->execute()) {
                    $verification_link = "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] . "?action=verify&token=" . $verification_token;
                    $subject = "Verify Your Goal Tracker Account";
                    $message = "
                        <h2>Welcome to Goal Tracker!</h2>
                        <p>Please click the link below to verify your account:</p>
                        <a href='$verification_link' style='background:#4CAF50;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;'>Verify Account</a>
                        <p>This link will expire in 24 hours.</p>
                    ";
                    
                    if (sendEmail($email, $subject, $message)) {
                        $success = "Registration successful! Please check your email to verify your account.";
                    } else {
                        $error = "Registration successful but failed to send verification email. Please contact support.";
                    }
                } else {
                    $error = "Registration failed. Please try again.";
                }
            }
        }
    }
    
    showRegisterForm($error, $success);
}

function handleLogin($conn) {
    $error = '';
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
        $password = trim($_POST['password']);
        
        if ($email && $password) {
            $stmt = $conn->prepare("SELECT id, password, is_verified FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($user = $result->fetch_assoc()) {
                if (!$user['is_verified']) {
                    $error = "Please verify your email before logging in.";
                } elseif (password_verify($password, $user['password'])) {
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_email'] = $email;
                    $_SESSION['last_activity'] = time();
                    
                    $conn->query("UPDATE users SET last_login = NOW() WHERE id = " . $user['id']);
                    header("Location: ?action=dashboard");
                    exit();
                } else {
                    $error = "Invalid email or password";
                }
            } else {
                $error = "Invalid email or password";
            }
        } else {
            $error = "Please fill in all fields";
        }
    }
    
    showLoginForm($error);
}

function handleVerification($conn) {
    $token = $_GET['token'] ?? '';
    $message = '';
    
    if ($token) {
        $stmt = $conn->prepare("SELECT id FROM users WHERE verification_token = ? AND is_verified = FALSE");
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $conn->query("UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = '$token'");
            $message = "Email verified successfully! You can now log in.";
        } else {
            $message = "Invalid or expired verification token.";
        }
    } else {
        $message = "Invalid verification link.";
    }
    
    showMessage($message, "?action=login", "Go to Login");
}

function handleForgotPassword($conn) {
    $error = '';
    $success = '';
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
        
        if ($email) {
            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND is_verified = TRUE");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $reset_token = generateToken();
                $reset_expires = date('Y-m-d H:i:s', strtotime('+1 hour'));
                
                $stmt = $conn->prepare("UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?");
                $stmt->bind_param("sss", $reset_token, $reset_expires, $email);
                $stmt->execute();
                
                $reset_link = "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] . "?action=reset&token=" . $reset_token;
                $subject = "Reset Your Goal Tracker Password";
                $message = "
                    <h2>Password Reset Request</h2>
                    <p>Click the link below to reset your password:</p>
                    <a href='$reset_link' style='background:#f44336;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;'>Reset Password</a>
                    <p>This link will expire in 1 hour.</p>
                ";
                
                sendEmail($email, $subject, $message);
                $success = "Password reset link sent to your email.";
            } else {
                $error = "Email not found or not verified.";
            }
        } else {
            $error = "Please enter a valid email address.";
        }
    }
    
    showForgotPasswordForm($error, $success);
}

function handleResetPassword($conn) {
    $token = $_GET['token'] ?? '';
    $error = '';
    $success = '';
    
    if (!$token) {
        showMessage("Invalid reset link.", "?action=login", "Go to Login");
        return;
    }
    
    $stmt = $conn->prepare("SELECT id FROM users WHERE reset_token = ? AND reset_expires > NOW()");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        showMessage("Invalid or expired reset token.", "?action=login", "Go to Login");
        return;
    }
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $password = trim($_POST['password']);
        $confirm_password = trim($_POST['confirm_password']);
        
        if (strlen($password) < 6) {
            $error = "Password must be at least 6 characters";
        } elseif ($password !== $confirm_password) {
            $error = "Passwords do not match";
        } else {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE reset_token = ?");
            $stmt->bind_param("ss", $hashed_password, $token);
            
            if ($stmt->execute()) {
                $success = "Password reset successfully! You can now log in.";
            } else {
                $error = "Failed to reset password. Please try again.";
            }
        }
    }
    
    if ($success) {
        showMessage($success, "?action=login", "Go to Login");
    } else {
        showResetPasswordForm($token, $error);
    }
}

function handleAddGoal($conn) {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $title = trim($_POST['title']);
        $description = trim($_POST['description']);
        $deadline = $_POST['deadline'];
        $is_hidden = isset($_POST['is_hidden']) ? 1 : 0;
        
        if ($title && $deadline) {
            $stmt = $conn->prepare("INSERT INTO goals (user_id, title, description, deadline, is_hidden) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("isssi", $_SESSION['user_id'], $title, $description, $deadline, $is_hidden);
            $stmt->execute();
        }
    }
    
    header("Location: ?action=dashboard");
    exit();
}

function handleEditGoal($conn) {
    $goal_id = $_POST['goal_id'] ?? 0;
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST' && $goal_id) {
        $title = trim($_POST['title']);
        $description = trim($_POST['description']);
        $deadline = $_POST['deadline'];
        
        if ($title && $deadline) {
            $stmt = $conn->prepare("UPDATE goals SET title = ?, description = ?, deadline = ? WHERE id = ? AND user_id = ?");
            $stmt->bind_param("sssii", $title, $description, $deadline, $goal_id, $_SESSION['user_id']);
            $stmt->execute();
        }
    }
    
    header("Location: " . ($_SERVER['HTTP_REFERER'] ?? "?action=dashboard"));
    exit();
}

function handleDeleteGoal($conn) {
    $goal_id = $_GET['id'] ?? 0;
    
    if ($goal_id) {
        $stmt = $conn->prepare("DELETE FROM goals WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $goal_id, $_SESSION['user_id']);
        $stmt->execute();
    }
    
    header("Location: " . ($_SERVER['HTTP_REFERER'] ?? "?action=dashboard"));
    exit();
}

function handleCompleteGoal($conn) {
    $goal_id = $_GET['id'] ?? 0;
    $status = $_GET['status'] ?? 'completed';
    
    if ($goal_id) {
        $completed_at = ($status === 'completed') ? 'NOW()' : 'NULL';
        $conn->query("UPDATE goals SET status = '$status', completed_at = $completed_at WHERE id = $goal_id AND user_id = " . $_SESSION['user_id']);
    }
    
    header("Location: " . ($_SERVER['HTTP_REFERER'] ?? "?action=dashboard"));
    exit();
}

function handleHiddenVerification($conn) {
    $error = '';
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $password = trim($_POST['password']);
        
        $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        
        if (password_verify($password, $user['password'])) {
            $_SESSION['hidden_access'] = true;
            $_SESSION['hidden_access_time'] = time();
            header("Location: ?action=hidden_goals");
            exit();
        } else {
            $error = "Incorrect password";
        }
    }
    
    showHiddenVerificationForm($error);
}

function showDashboard($conn) {
    // Check if hidden access has expired (5 minutes)
    if (isset($_SESSION['hidden_access']) && (time() - $_SESSION['hidden_access_time'] > 300)) {
        unset($_SESSION['hidden_access']);
        unset($_SESSION['hidden_access_time']);
    }
    
    // Get statistics
    $user_id = $_SESSION['user_id'];
    $stats_query = $conn->query("
        SELECT 
            COUNT(*) as total_goals,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_goals,
            SUM(CASE WHEN is_hidden = 0 THEN 1 ELSE 0 END) as normal_goals,
            SUM(CASE WHEN is_hidden = 1 THEN 1 ELSE 0 END) as hidden_goals
        FROM goals WHERE user_id = $user_id
    ");
    $stats = $stats_query->fetch_assoc();
    
    // Get normal goals
    $search = $_GET['search'] ?? '';
    $filter = $_GET['filter'] ?? 'all';
    
    $where_clause = "WHERE user_id = $user_id AND is_hidden = 0";
    if ($search) {
        $search = $conn->real_escape_string($search);
        $where_clause .= " AND (title LIKE '%$search%' OR description LIKE '%$search%')";
    }
    if ($filter === 'completed') {
        $where_clause .= " AND status = 'completed'";
    } elseif ($filter === 'pending') {
        $where_clause .= " AND status = 'pending'";
    } elseif ($filter === 'overdue') {
        $where_clause .= " AND deadline < CURDATE() AND status = 'pending'";
    }
    
    $goals_query = $conn->query("SELECT * FROM goals $where_clause ORDER BY deadline ASC, created_at DESC");
    
    include 'template_dashboard.php';
}

function showHiddenGoals($conn) {
    if (!isset($_SESSION['hidden_access'])) {
        header("Location: ?action=verify_hidden");
        exit();
    }
    
    // Get hidden goals
    $user_id = $_SESSION['user_id'];
    $search = $_GET['search'] ?? '';
    $filter = $_GET['filter'] ?? 'all';
    
    $where_clause = "WHERE user_id = $user_id AND is_hidden = 1";
    if ($search) {
        $search = $conn->real_escape_string($search);
        $where_clause .= " AND (title LIKE '%$search%' OR description LIKE '%$search%')";
    }
    if ($filter === 'completed') {
        $where_clause .= " AND status = 'completed'";
    } elseif ($filter === 'pending') {
        $where_clause .= " AND status = 'pending'";
    }
    
    $hidden_goals_query = $conn->query("SELECT * FROM goals $where_clause ORDER BY deadline ASC, created_at DESC");
    
    include 'template_hidden_goals.php';
}

// Template Functions
function showRegisterForm($error = '', $success = '') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Register - Goal Tracker</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="auth-container">
            <div class="auth-card">
                <h1>🎯 Goal Tracker</h1>
                <h2>Create Account</h2>
                
                <?php if ($error): ?>
                    <div class="alert error"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert success"><?= htmlspecialchars($success) ?></div>
                <?php endif; ?>
                
                <form method="POST" class="auth-form">
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required minlength="6">
                    </div>
                    
                    <div class="form-group">
                        <label for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" name="confirm_password" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Create Account</button>
                </form>
                
                <div class="auth-links">
                    <a href="?action=login">Already have an account? Login</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
}

function showLoginForm($error = '') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Goal Tracker</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="auth-container">
            <div class="auth-card">
                <h1>🎯 Goal Tracker</h1>
                <h2>Login</h2>
                
                <?php if ($error): ?>
                    <div class="alert error"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
                
                <form method="POST" class="auth-form">
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
                
                <div class="auth-links">
                    <a href="?action=register">Don't have an account? Register</a>
                    <a href="?action=forgot">Forgot Password?</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
}

function showForgotPasswordForm($error = '', $success = '') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Forgot Password - Goal Tracker</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="auth-container">
            <div class="auth-card">
                <h1>🎯 Goal Tracker</h1>
                <h2>Forgot Password</h2>
                
                <?php if ($error): ?>
                    <div class="alert error"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert success"><?= htmlspecialchars($success) ?></div>
                <?php endif; ?>
                
                <form method="POST" class="auth-form">
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Send Reset Link</button>
                </form>
                
                <div class="auth-links">
                    <a href="?action=login">Back to Login</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
}

function showResetPasswordForm($token, $error = '') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Password - Goal Tracker</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="auth-container">
            <div class="auth-card">
                <h1>🎯 Goal Tracker</h1>
                <h2>Reset Password</h2>
                
                <?php if ($error): ?>
                    <div class="alert error"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
                
                <form method="POST" class="auth-form">
                    <div class="form-group">
                        <label for="password">New Password</label>
                        <input type="password" id="password" name="password" required minlength="6">
                    </div>
                    
                    <div class="form-group">
                        <label for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" name="confirm_password" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Reset Password</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    <?php
}

function showHiddenVerificationForm($error = '') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Access - Goal Tracker</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="auth-container">
            <div class="auth-card">
                <h1>🔒 Hidden Goals</h1>
                <h2>Verify Your Identity</h2>
                <p>Please enter your password to access hidden goals.</p>
                
                <?php if ($error): ?>
                    <div class="alert error"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
                
                <form method="POST" class="auth-form">
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Verify Access</button>
                </form>
                
                <div class="auth-links">
                    <a href="?action=dashboard">Back to Dashboard</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
}

function showMessage($message, $link = null, $link_text = 'Continue') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Goal Tracker</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="auth-container">
            <div class="auth-card">
                <h1>🎯 Goal Tracker</h1>
                <div class="message">
                    <p><?= htmlspecialchars($message) ?></p>
                    <?php if ($link): ?>
                        <a href="<?= htmlspecialchars($link) ?>" class="btn btn-primary"><?= htmlspecialchars($link_text) ?></a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
}

// Inline templates for dashboard and hidden goals
if (!function_exists('include')) {
    function template_dashboard($stats, $goals_query, $search, $filter) {
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Dashboard - Goal Tracker</title>
            <link rel="stylesheet" href="style.css">
        </head>
        <body>
            <div class="dashboard">
                <header class="dashboard-header">
                    <h1>🎯 Goal Tracker</h1>
                    <div class="user-info">
                        Welcome, <?= htmlspecialchars($_SESSION['user_email']) ?>
                        <a href="?action=logout" class="btn btn-small">Logout</a>
                    </div>
                </header>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3><?= $stats['total_goals'] ?? 0 ?></h3>
                        <p>Total Goals</p>
                    </div>
                    <div class="stat-card">
                        <h3><?= $stats['completed_goals'] ?? 0 ?></h3>
                        <p>Completed</p>
                    </div>
                    <div class="stat-card">
                        <h3><?= $stats['normal_goals'] ?? 0 ?></h3>
                        <p>Normal Goals</p>
                    </div>
                    <div class="stat-card">
                        <h3><?= $stats['hidden_goals'] ?? 0 ?></h3>
                        <p>Hidden Goals</p>
                    </div>
                </div>
                
                <div class="progress-bar">
                    <?php 
                    $progress = $stats['total_goals'] > 0 ? ($stats['completed_goals'] / $stats['total_goals']) * 100 : 0;
                    ?>
                    <div class="progress-fill" style="width: <?= $progress ?>%"></div>
                    <span class="progress-text"><?= round($progress) ?>% Complete</span>
                </div>
                
                <div class="main-content">
                    <div class="content-header">
                        <h2>My Goals</h2>
                        <div class="actions">
                            <button onclick="showAddGoalModal()" class="btn btn-primary">+ Add Goal</button>
                            <a href="?action=hidden_goals" class="btn btn-secondary">🔒 Hidden Goals</a>
                        </div>
                    </div>
                    
                    <div class="filters">
                        <form method="GET" class="filter-form">
                            <input type="hidden" name="action" value="dashboard">
                            <input type="search" name="search" placeholder="Search goals..." value="<?= htmlspecialchars($search) ?>">
                            <select name="filter">
                                <option value="all" <?= $filter === 'all' ? 'selected' : '' ?>>All Goals</option>
                                <option value="pending" <?= $filter === 'pending' ? 'selected' : '' ?>>Pending</option>
                                <option value="completed" <?= $filter === 'completed' ? 'selected' : '' ?>>Completed</option>
                                <option value="overdue" <?= $filter === 'overdue' ? 'selected' : '' ?>>Overdue</option>
                            </select>
                            <button type="submit" class="btn btn-small">Filter</button>
                        </form>
                    </div>
                    
                    <div class="goals-grid">
                        <?php if ($goals_query->num_rows === 0): ?>
                            <div class="empty-state">
                                <h3>No goals found</h3>
                                <p>Start by creating your first goal!</p>
                            </div>
                        <?php else: ?>
                            <?php while ($goal = $goals_query->fetch_assoc()): ?>
                                <div class="goal-card <?= $goal['status'] ?> <?= strtotime($goal['deadline']) < time() && $goal['status'] === 'pending' ? 'overdue' : '' ?>">
                                    <div class="goal-header">
                                        <h3><?= htmlspecialchars($goal['title']) ?></h3>
                                        <div class="goal-actions">
                                            <button onclick="editGoal(<?= $goal['id'] ?>, '<?= htmlspecialchars(addslashes($goal['title'])) ?>', '<?= htmlspecialchars(addslashes($goal['description'])) ?>', '<?= $goal['deadline'] ?>')" class="btn-icon">✏️</button>
                                            <a href="?action=delete_goal&id=<?= $goal['id'] ?>" onclick="return confirm('Are you sure?')" class="btn-icon">🗑️</a>
                                        </div>
                                    </div>
                                    
                                    <p class="goal-description"><?= htmlspecialchars($goal['description']) ?></p>
                                    
                                    <div class="goal-meta">
                                        <span class="deadline">📅 <?= date('M d, Y', strtotime($goal['deadline'])) ?></span>
                                        <span class="status status-<?= $goal['status'] ?>"><?= ucfirst($goal['status']) ?></span>
                                    </div>
                                    
                                    <div class="goal-footer">
                                        <?php if ($goal['status'] === 'pending'): ?>
                                            <a href="?action=complete_goal&id=<?= $goal['id'] ?>&status=completed" class="btn btn-success btn-small">✅ Complete</a>
                                        <?php else: ?>
                                            <a href="?action=complete_goal&id=<?= $goal['id'] ?>&status=pending" class="btn btn-secondary btn-small">↩️ Undo</a>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endwhile; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            
            <!-- Add Goal Modal -->
            <div id="addGoalModal" class="modal">
                <div class="modal-content">
                    <span class="close" onclick="closeModal('addGoalModal')">&times;</span>
                    <h2>Add New Goal</h2>
                    <form action="?action=add_goal" method="POST">
                        <div class="form-group">
                            <label for="title">Title *</label>
                            <input type="text" id="title" name="title" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="description">Description</label>
                            <textarea id="description" name="description" rows="3"></textarea>
                        </div>
                        
                        <div class="form-group">
                            <label for="deadline">Deadline *</label>
                            <input type="date" id="deadline" name="deadline" required min="<?= date('Y-m-d') ?>">
                        </div>
                        
                        <div class="form-group">
                            <label class="checkbox-label">
                                <input type="checkbox" name="is_hidden"> Make this a hidden goal
                            </label>
                        </div>
                        
                        <div class="modal-actions">
                            <button type="button" onclick="closeModal('addGoalModal')" class="btn btn-secondary">Cancel</button>
                            <button type="submit" class="btn btn-primary">Add Goal</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Edit Goal Modal -->
            <div id="editGoalModal" class="modal">
                <div class="modal-content">
                    <span class="close" onclick="closeModal('editGoalModal')">&times;</span>
                    <h2>Edit Goal</h2>
                    <form action="?action=edit_goal" method="POST">
                        <input type="hidden" id="edit_goal_id" name="goal_id">
                        
                        <div class="form-group">
                            <label for="edit_title">Title *</label>
                            <input type="text" id="edit_title" name="title" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="edit_description">Description</label>
                            <textarea id="edit_description" name="description" rows="3"></textarea>
                        </div>
                        
                        <div class="form-group">
                            <label for="edit_deadline">Deadline *</label>
                            <input type="date" id="edit_deadline" name="deadline" required>
                        </div>
                        
                        <div class="modal-actions">
                            <button type="button" onclick="closeModal('editGoalModal')" class="btn btn-secondary">Cancel</button>
                            <button type="submit" class="btn btn-primary">Update Goal</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <script>
                function showAddGoalModal() {
                    document.getElementById('addGoalModal').style.display = 'block';
                }
                
                function editGoal(id, title, description, deadline) {
                    document.getElementById('edit_goal_id').value = id;
                    document.getElementById('edit_title').value = title;
                    document.getElementById('edit_description').value = description;
                    document.getElementById('edit_deadline').value = deadline;
                    document.getElementById('editGoalModal').style.display = 'block';
                }
                
                function closeModal(modalId) {
                    document.getElementById(modalId).style.display = 'none';
                }
                
                window.onclick = function(event) {
                    if (event.target.classList.contains('modal')) {
                        event.target.style.display = 'none';
                    }
                }
            </script>
        </body>
        </html>
        <?php
    }
}

// Include the template functions inline since we can't use separate files
if ($action === 'dashboard' && isLoggedIn()) {
    // Check if hidden access has expired (5 minutes)
    if (isset($_SESSION['hidden_access']) && (time() - $_SESSION['hidden_access_time'] > 300)) {
        unset($_SESSION['hidden_access']);
        unset($_SESSION['hidden_access_time']);
    }
    
    // Get statistics
    $user_id = $_SESSION['user_id'];
    $stats_query = $conn->query("
        SELECT 
            COUNT(*) as total_goals,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_goals,
            SUM(CASE WHEN is_hidden = 0 THEN 1 ELSE 0 END) as normal_goals,
            SUM(CASE WHEN is_hidden = 1 THEN 1 ELSE 0 END) as hidden_goals
        FROM goals WHERE user_id = $user_id
    ");
    $stats = $stats_query->fetch_assoc();
    
    // Get normal goals
    $search = $_GET['search'] ?? '';
    $filter = $_GET['filter'] ?? 'all';
    
    $where_clause = "WHERE user_id = $user_id AND is_hidden = 0";
    if ($search) {
        $search = $conn->real_escape_string($search);
        $where_clause .= " AND (title LIKE '%$search%' OR description LIKE '%$search%')";
    }
    if ($filter === 'completed') {
        $where_clause .= " AND status = 'completed'";
    } elseif ($filter === 'pending') {
        $where_clause .= " AND status = 'pending'";
    } elseif ($filter === 'overdue') {
        $where_clause .= " AND deadline < CURDATE() AND status = 'pending'";
    }
    
    $goals_query = $conn->query("SELECT * FROM goals $where_clause ORDER BY deadline ASC, created_at DESC");
    
    // Dashboard template
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard - Goal Tracker</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="dashboard">
            <header class="dashboard-header">
                <h1>🎯 Goal Tracker</h1>
                <div class="user-info">
                    Welcome, <?= htmlspecialchars($_SESSION['user_email']) ?>
                    <a href="?action=logout" class="btn btn-small">Logout</a>
                </div>
            </header>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3><?= $stats['total_goals'] ?? 0 ?></h3>
                    <p>Total Goals</p>
                </div>
                <div class="stat-card">
                    <h3><?= $stats['completed_goals'] ?? 0 ?></h3>
                    <p>Completed</p>
                </div>
                <div class="stat-card">
                    <h3><?= $stats['normal_goals'] ?? 0 ?></h3>
                    <p>Normal Goals</p>
                </div>
                <div class="stat-card">
                    <h3><?= $stats['hidden_goals'] ?? 0 ?></h3>
                    <p>Hidden Goals</p>
                </div>
            </div>
            
            <div class="progress-bar">
                <?php 
                $progress = $stats['total_goals'] > 0 ? ($stats['completed_goals'] / $stats['total_goals']) * 100 : 0;
                ?>
                <div class="progress-fill" style="width: <?= $progress ?>%"></div>
                <span class="progress-text"><?= round($progress) ?>% Complete</span>
            </div>
            
            <div class="main-content">
                <div class="content-header">
                    <h2>My Goals</h2>
                    <div class="actions">
                        <button onclick="showAddGoalModal()" class="btn btn-primary">+ Add Goal</button>
                        <a href="?action=hidden_goals" class="btn btn-secondary">🔒 Hidden Goals</a>
                    </div>
                </div>
                
                <div class="filters">
                    <form method="GET" class="filter-form">
                        <input type="hidden" name="action" value="dashboard">
                        <input type="search" name="search" placeholder="Search goals..." value="<?= htmlspecialchars($search) ?>">
                        <select name="filter">
                            <option value="all" <?= $filter === 'all' ? 'selected' : '' ?>>All Goals</option>
                            <option value="pending" <?= $filter === 'pending' ? 'selected' : '' ?>>Pending</option>
                            <option value="completed" <?= $filter === 'completed' ? 'selected' : '' ?>>Completed</option>
                            <option value="overdue" <?= $filter === 'overdue' ? 'selected' : '' ?>>Overdue</option>
                        </select>
                        <button type="submit" class="btn btn-small">Filter</button>
                    </form>
                </div>
                
                <div class="goals-grid">
                    <?php if ($goals_query->num_rows === 0): ?>
                        <div class="empty-state">
                            <h3>No goals found</h3>
                            <p>Start by creating your first goal!</p>
                        </div>
                    <?php else: ?>
                        <?php while ($goal = $goals_query->fetch_assoc()): ?>
                            <div class="goal-card <?= $goal['status'] ?> <?= strtotime($goal['deadline']) < time() && $goal['status'] === 'pending' ? 'overdue' : '' ?>">
                                <div class="goal-header">
                                    <h3><?= htmlspecialchars($goal['title']) ?></h3>
                                    <div class="goal-actions">
                                        <button onclick="editGoal(<?= $goal['id'] ?>, '<?= htmlspecialchars(addslashes($goal['title'])) ?>', '<?= htmlspecialchars(addslashes($goal['description'])) ?>', '<?= $goal['deadline'] ?>')" class="btn-icon">✏️</button>
                                        <a href="?action=delete_goal&id=<?= $goal['id'] ?>" onclick="return confirm('Are you sure?')" class="btn-icon">🗑️</a>
                                    </div>
                                </div>
                                
                                <p class="goal-description"><?= htmlspecialchars($goal['description']) ?></p>
                                
                                <div class="goal-meta">
                                    <span class="deadline">📅 <?= date('M d, Y', strtotime($goal['deadline'])) ?></span>
                                    <span class="status status-<?= $goal['status'] ?>"><?= ucfirst($goal['status']) ?></span>
                                </div>
                                
                                <div class="goal-footer">
                                    <?php if ($goal['status'] === 'pending'): ?>
                                        <a href="?action=complete_goal&id=<?= $goal['id'] ?>&status=completed" class="btn btn-success btn-small">✅ Complete</a>
                                    <?php else: ?>
                                        <a href="?action=complete_goal&id=<?= $goal['id'] ?>&status=pending" class="btn btn-secondary btn-small">↩️ Undo</a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endwhile; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- Add Goal Modal -->
        <div id="addGoalModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('addGoalModal')">&times;</span>
                <h2>Add New Goal</h2>
                <form action="?action=add_goal" method="POST">
                    <div class="form-group">
                        <label for="title">Title *</label>
                        <input type="text" id="title" name="title" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="description">Description</label>
                        <textarea id="description" name="description" rows="3"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="deadline">Deadline *</label>
                        <input type="date" id="deadline" name="deadline" required min="<?= date('Y-m-d') ?>">
                    </div>
                    
                    <div class="form-group">
                        <label class="checkbox-label">
                            <input type="checkbox" name="is_hidden"> Make this a hidden goal
                        </label>
                    </div>
                    
                    <div class="modal-actions">
                        <button type="button" onclick="closeModal('addGoalModal')" class="btn btn-secondary">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Goal</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Edit Goal Modal -->
        <div id="editGoalModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('editGoalModal')">&times;</span>
                <h2>Edit Goal</h2>
                <form action="?action=edit_goal" method="POST">
                    <input type="hidden" id="edit_goal_id" name="goal_id">
                    
                    <div class="form-group">
                        <label for="edit_title">Title *</label>
                        <input type="text" id="edit_title" name="title" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="edit_description">Description</label>
                        <textarea id="edit_description" name="description" rows="3"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="edit_deadline">Deadline *</label>
                        <input type="date" id="edit_deadline" name="deadline" required>
                    </div>
                    
                    <div class="modal-actions">
                        <button type="button" onclick="closeModal('editGoalModal')" class="btn btn-secondary">Cancel</button>
                        <button type="submit" class="btn btn-primary">Update Goal</button>
                    </div>
                </form>
            </div>
        </div>
        
        <script>
            function showAddGoalModal() {
                document.getElementById('addGoalModal').style.display = 'block';
            }
            
            function editGoal(id, title, description, deadline) {
                document.getElementById('edit_goal_id').value = id;
                document.getElementById('edit_title').value = title;
                document.getElementById('edit_description').value = description;
                document.getElementById('edit_deadline').value = deadline;
                document.getElementById('editGoalModal').style.display = 'block';
            }
            
            function closeModal(modalId) {
                document.getElementById(modalId).style.display = 'none';
            }
            
            window.onclick = function(event) {
                if (event.target.classList.contains('modal')) {
                    event.target.style.display = 'none';
                }
            }
        </script>
    </body>
    </html>
    <?php
    exit();
}

// Hidden Goals Template
if ($action === 'hidden_goals' && isLoggedIn()) {
    if (!isset($_SESSION['hidden_access'])) {
        header("Location: ?action=verify_hidden");
        exit();
    }
    
    // Get hidden goals
    $user_id = $_SESSION['user_id'];
    $search = $_GET['search'] ?? '';
    $filter = $_GET['filter'] ?? 'all';
    
    $where_clause = "WHERE user_id = $user_id AND is_hidden = 1";
    if ($search) {
        $search = $conn->real_escape_string($search);
        $where_clause .= " AND (title LIKE '%$search%' OR description LIKE '%$search%')";
    }
    if ($filter === 'completed') {
        $where_clause .= " AND status = 'completed'";
    } elseif ($filter === 'pending') {
        $where_clause .= " AND status = 'pending'";
    }
    
    $hidden_goals_query = $conn->query("SELECT * FROM goals $where_clause ORDER BY deadline ASC, created_at DESC");
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Hidden Goals - Goal Tracker</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
        <div class="dashboard">
            <header class="dashboard-header">
                <h1>🔒 Hidden Goals</h1>
                <div class="user-info">
                    <a href="?action=dashboard" class="btn btn-small">← Dashboard</a>
                    <a href="?action=logout" class="btn btn-small">Logout</a>
                </div>
            </header>
            
            <div class="main-content">
                <div class="content-header">
                    <h2>My Hidden Goals</h2>
                    <div class="actions">
                        <button onclick="showAddGoalModal()" class="btn btn-primary">+ Add Hidden Goal</button>
                    </div>
                </div>
                
                <div class="filters">
                    <form method="GET" class="filter-form">
                        <input type="hidden" name="action" value="hidden_goals">
                        <input type="search" name="search" placeholder="Search hidden goals..." value="<?= htmlspecialchars($search) ?>">
                        <select name="filter">
                            <option value="all" <?= $filter === 'all' ? 'selected' : '' ?>>All Goals</option>
                            <option value="pending" <?= $filter === 'pending' ? 'selected' : '' ?>>Pending</option>
                            <option value="completed" <?= $filter === 'completed' ? 'selected' : '' ?>>Completed</option>
                        </select>
                        <button type="submit" class="btn btn-small">Filter</button>
                    </form>
                </div>
                
                <div class="goals-grid">
                    <?php if ($hidden_goals_query->num_rows === 0): ?>
                        <div class="empty-state">
                            <h3>No hidden goals found</h3>
                            <p>Create your first hidden goal to keep it private!</p>
                        </div>
                    <?php else: ?>
                        <?php while ($goal = $hidden_goals_query->fetch_assoc()): ?>
                            <div class="goal-card <?= $goal['status'] ?> <?= strtotime($goal['deadline']) < time() && $goal['status'] === 'pending' ? 'overdue' : '' ?> hidden">
                                <div class="goal-header">
                                    <h3>🔒 <?= htmlspecialchars($goal['title']) ?></h3>
                                    <div class="goal-actions">
                                        <button onclick="editGoal(<?= $goal['id'] ?>, '<?= htmlspecialchars(addslashes($goal['title'])) ?>', '<?= htmlspecialchars(addslashes($goal['description'])) ?>', '<?= $goal['deadline'] ?>')" class="btn-icon">✏️</button>
                                        <a href="?action=delete_goal&id=<?= $goal['id'] ?>" onclick="return confirm('Are you sure?')" class="btn-icon">🗑️</a>
                                    </div>
                                </div>
                                
                                <p class="goal-description"><?= htmlspecialchars($goal['description']) ?></p>
                                
                                <div class="goal-meta">
                                    <span class="deadline">📅 <?= date('M d, Y', strtotime($goal['deadline'])) ?></span>
                                    <span class="status status-<?= $goal['status'] ?>"><?= ucfirst($goal['status']) ?></span>
                                </div>
                                
                                <div class="goal-footer">
                                    <?php if ($goal['status'] === 'pending'): ?>
                                        <a href="?action=complete_goal&id=<?= $goal['id'] ?>&status=completed" class="btn btn-success btn-small">✅ Complete</a>
                                    <?php else: ?>
                                        <a href="?action=complete_goal&id=<?= $goal['id'] ?>&status=pending" class="btn btn-secondary btn-small">↩️ Undo</a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endwhile; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- Add Hidden Goal Modal -->
        <div id="addGoalModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('addGoalModal')">&times;</span>
                <h2>Add New Hidden Goal</h2>
                <form action="?action=add_goal" method="POST">
                    <input type="hidden" name="is_hidden" value="1">
                    
                    <div class="form-group">
                        <label for="title">Title *</label>
                        <input type="text" id="title" name="title" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="description">Description</label>
                        <textarea id="description" name="description" rows="3"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="deadline">Deadline *</label>
                        <input type="date" id="deadline" name="deadline" required min="<?= date('Y-m-d') ?>">
                    </div>
                    
                    <div class="modal-actions">
                        <button type="button" onclick="closeModal('addGoalModal')" class="btn btn-secondary">Cancel</button>
                        <button type="submit" class="btn btn-primary">Add Hidden Goal</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Edit Goal Modal -->
        <div id="editGoalModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('editGoalModal')">&times;</span>
                <h2>Edit Hidden Goal</h2>
                <form action="?action=edit_goal" method="POST">
                    <input type="hidden" id="edit_goal_id" name="goal_id">
                    
                    <div class="form-group">
                        <label for="edit_title">Title *</label>
                        <input type="text" id="edit_title" name="title" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="edit_description">Description</label>
                        <textarea id="edit_description" name="description" rows="3"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="edit_deadline">Deadline *</label>
                        <input type="date" id="edit_deadline" name="deadline" required>
                    </div>
                    
                    <div class="modal-actions">
                        <button type="button" onclick="closeModal('editGoalModal')" class="btn btn-secondary">Cancel</button>
                        <button type="submit" class="btn btn-primary">Update Goal</button>
                    </div>
                </form>
            </div>
        </div>
        
        <script>
            function showAddGoalModal() {
                document.getElementById('addGoalModal').style.display = 'block';
            }
            
            function editGoal(id, title, description, deadline) {
                document.getElementById('edit_goal_id').value = id;
                document.getElementById('edit_title').value = title;
                document.getElementById('edit_description').value = description;
                document.getElementById('edit_deadline').value = deadline;
                document.getElementById('editGoalModal').style.display = 'block';
            }
            
            function closeModal(modalId) {
                document.getElementById(modalId).style.display = 'none';
            }
            
            window.onclick = function(event) {
                if (event.target.classList.contains('modal')) {
                    event.target.style.display = 'none';
                }
            }
        </script>
    </body>
    </html>
    <?php
    exit();
}
?>
