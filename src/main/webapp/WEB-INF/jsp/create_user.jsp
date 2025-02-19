<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <script>
        // JavaScript function to toggle the service and location fields
        function toggleServiceLocation() {
            var role = document.getElementById("role").value;
            var serviceField = document.getElementById("serviceField");
            var locationField = document.getElementById("locationField");

            if (role === "AGENT") {
                serviceField.style.display = "block";
                locationField.style.display = "block";
            } else {
                serviceField.style.display = "none";
                locationField.style.display = "none";
            }
        }
    </script>
</head>
<body>

    <h1>Admin Panel - Manage Users</h1>

    <!-- Form to create a new user -->
    <h2>Create a New User</h2>
    <form action="/createUser" method="post">
        <label>Prénom:</label>
        <input type="text" name="prenom" required><br>

        <label>Nom:</label>
        <input type="text" name="nom" required><br>

        <label>Numéro Téléphone:</label>
        <input type="text" name="numeroTel" required><br>

        <label>Password:</label>
        <input type="password" name="password" required><br>

        <label>Role:</label>
        <select name="role" id="role" required onchange="toggleServiceLocation()">
            <option value="ADMIN">Admin</option>
            <option value="AGENT">Agent</option>
            <option value="CLIENT">Client</option>
        </select><br>

        <!-- Service selection (only for agents) -->
        <div id="serviceField" style="display: none;">
            <label>Service:</label>
            <select name="serviceId">
                <c:forEach var="service" items="${services}">
                    <option value="${service.id}">${service.name}</option>
                </c:forEach>
            </select><br>
        </div>

        <!-- Location selection (only for agents) -->
        <div id="locationField" style="display: none;">
            <label>Location:</label>
            <select name="locationId">
                <c:forEach var="location" items="${locations}">
                    <option value="${location.id}">${location.name}</option>
                </c:forEach>
            </select><br>
        </div>

        <button type="submit">Create User</button>
    </form>

    <!-- Agents Table -->
    <h2>Agents</h2>
    <table border="1">
        <tr>
            <th>ID</th>
            <th>Prénom</th>
            <th>Nom</th>
            <th>Numéro Téléphone</th>
            <th>Service</th>
            <th>Location</th>
            <th>Actions</th> 
        </tr>
        <c:forEach var="agent" items="${agents}">
            <tr>
                <td>${agent.id}</td>
                <td>${agent.prenom}</td>
                <td>${agent.nom}</td>
                <td>${agent.numeroTel}</td>
                <td>${agent.service.name}</td>
                <td>${agent.location.name}</td>
                <td>
                    <a href="/deleteUser/${agent.id}">Delete</a>
                </td>
            </tr>
        </c:forEach>
    </table>

    <!-- Clients Table -->
    <h2>Clients</h2>
    <table border="1">
        <tr>
            <th>ID</th>
            <th>Prénom</th>
            <th>Nom</th>
            <th>Numéro Téléphone</th>
            <th>Actions</th>
        </tr>
        <c:forEach var="client" items="${clients}">
            <tr>
                <td>${client.id}</td>
                <td>${client.prenom}</td>
                <td>${client.nom}</td>
                <td>${client.numeroTel}</td>
                <td>
                    <a href="/deleteUser/${client.id}">Delete</a>
                </td>
            </tr>
        </c:forEach>
    </table>

    <!-- Admins Table -->
    <h2>Admins</h2>
    <table border="1">
        <tr>
            <th>ID</th>
            <th>Prénom</th>
            <th>Nom</th>
            <th>Numéro Téléphone</th>
            <th>Actions</th> 
        </tr>
        <c:forEach var="admin" items="${admins}">
            <tr>
                <td>${admin.id}</td>
                <td>${admin.prenom}</td>
                <td>${admin.nom}</td>
                <td>${admin.numeroTel}</td>
                <td>
                    <a href="/deleteUser/${admin.id}">Delete</a>
                </td>
            </tr>
        </c:forEach>
    </table>

</body>
</html>
