<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login Page</title>
    <link rel="stylesheet" type="text/css" href="styles.css">
</head>
<body>
    <h1>Login Panel</h1>

    <!-- Login Form -->
    <form action="/login" method="post">
        <label>Numéro Téléphone:</label>
        <input type="text" name="numeroTel" required><br>
    
        <label>Password:</label>
        <input type="password" name="password" required><br>
    
        <button type="submit">Login</button>
    </form>
    

    <c:if test="${not empty error}">
        <p style="color: red;">${error}</p>
    </c:if>

    <c:if test="${param.logout != null}">
        <p style="color: green;">You have been logged out.</p>
    </c:if>

</body>
</html>

<script>
    function logLoginData(event) {
        event.preventDefault(); // Prevent form submission to allow logging
    
        // Get form inputs
        const numeroTel = document.querySelector('input[name="numeroTel"]').value;
        const password = document.querySelector('input[name="password"]').value;
    
        // Log the values to the console
        console.log('Login Attempt:');
        console.log('Numéro Téléphone:', numeroTel);
        console.log('Password:', password);
    
        // Now submit the form after logging the data
        event.target.submit();
    }
    </script>