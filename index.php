<?php
// Redirect to the new separated encrypt page
header('Location: encrypt.php');
exit;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0;url=encrypt.php">
    <title>Redirecting to Encryptor...</title>
    <script>
        window.location.href = 'encrypt.php';
    </script>
</head>
<body>
    <p>Redirecting to encryption page...</p>
    <p>If you are not redirected automatically, <a href="encrypt.php">click here</a>.</p>
</body>
</html>