<?php
session_start();

include '../php/db_connect.php'; 

// Retrieve form data
$email = $_POST['email'];
$password = $_POST['password'];

// Validate inputs
if (empty($email) || empty($password)) {
    die("Email and password are required.");
}

// Retrieve user data from the database based on email
$stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();
$stmt->bind_result($id, $hashedPassword);

if ($stmt->num_rows == 1) {
    $stmt->fetch();
    // Verify password
    if (password_verify($password, $hashedPassword)) {
        // Password is correct, set session variables and redirect to dashboard
        $_SESSION['user_id'] = $id;
        $_SESSION['user_email'] = $email;
        // Redirect to dashboard or homepage
        header("Location: ../dashboard.php");
        exit();
    } else {
        echo "Incorrect password";
    }
} else {
    echo "User not found";
}

// Close statement and connection
$stmt->close();
$conn->close();
?>
