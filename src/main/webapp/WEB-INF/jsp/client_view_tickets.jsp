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

        <div class="client1">
            <h2 class="green">Mes tickets</h2>

            <table border="1"> 
                <tr>
                    <th>Numéro de Ticket</th>
                    <th>Date de Création</th>
                    <th>Statut</th>
                    <th>Position dans la file</th>
                    <th>Service</th>
                    <th>Localisation</th>
                </tr>
                <c:forEach var="ticket" items="${tickets}">
                    <tr>
                        <td>${ticket.ticketNumber}</td>
                        <td>${ticket.createdAt}</td>
                        <td>${ticket.status}</td>
                        <td>${ticket.positionInQueue}</td>
                        <td>${ticket.service.name}</td>
                        <td>${ticket.location.name}</td>
                    </tr>
                </c:forEach>
            </table>

            <!-- Navigation links -->
            <div class="nav">
                <ul>
                    <li><a href="/client_obtain_ticket">Obtenir un ticket</a></li>
                    <li><a href="/client_home">Accueil client</a></li>
                    <li><a href="/logout">Se déconnecter</a></li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
