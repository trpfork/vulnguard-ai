<?php
/**
 * VulnGuard AI — Mock Vulnerable PHP File
 * Used to test the scanner agent.
 *
 * Intentional vulnerabilities for testing:
 * 1. Broken Access Control (CWE-639) — line 24
 * 2. SQL Injection (CWE-89)          — line 38
 * 3. Reflected XSS (CWE-79)          — line 52
 * 4. Hardcoded Credential (CWE-798)  — line 14
 */

// CWE-798: Hardcoded database credentials
$db_password = "super_secret_pass123";
$db = new mysqli("localhost", "root", $db_password, "users_db");

function getUserProfile($user_id) {
    global $db;

    // CWE-639: Broken Access Control
    // No check that the requesting user is authorized to view this profile.
    // Any authenticated user can pass any user_id and read another user's data.
    $result = $db->query("SELECT * FROM users WHERE id = " . $user_id);
    return $result->fetch_assoc();
}

function searchUsers($query) {
    global $db;

    // CWE-89: SQL Injection
    // $query is unsanitized user input concatenated directly into SQL
    $sql = "SELECT id, username, email FROM users WHERE username LIKE '%" . $query . "%'";
    $result = $db->query($sql);
    $rows = [];
    while ($row = $result->fetch_assoc()) {
        $rows[] = $row;
    }
    return $rows;
}

function renderGreeting() {
    // CWE-79: Reflected XSS
    // $_GET['name'] is printed directly without escaping
    $name = $_GET['name'];
    echo "<h1>Welcome, " . $name . "!</h1>";
}

// Entry point
if (isset($_GET['user_id'])) {
    $profile = getUserProfile($_GET['user_id']);
    echo json_encode($profile);
} elseif (isset($_GET['search'])) {
    $results = searchUsers($_GET['search']);
    echo json_encode($results);
} elseif (isset($_GET['name'])) {
    renderGreeting();
}
?>
