<%@ page session="true" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Client - Gestion File</title>
</head>
<body>
    <div class="client">
        <h1>Client - Gestion File</h1>
        <div> 
            
            <!-- Display user details in your JSP page -->
            <c:if test="${not empty user}">
                <p>BIenvenue, ${user.prenom} ${user.nom}</p>
                <!-- <p>Phone: ${user.numeroTel}</p>
                <p>ID: ${user.id}</p> -->
            </c:if>
            <c:if test="${empty user}">
                <p>Utilisateur introuvable!</p>
            </c:if>

            <div class="nav">
                <ul> 
                    <li><a href="/client_view_tickets">Voir mes tickets</a></li>
                    <li><a href="/client_obtain_ticket">Obtenir un ticket</a></li>
                    <li><a href="/logout">Se déconnecter</a></li>
                </ul>
            </div>

        </div>
    </div>
</body>
</html>
