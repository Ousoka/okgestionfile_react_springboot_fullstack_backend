
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>


<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Ticket - OK Gestion File</title>
</head>
<body>
    <h1>Client - Gestion File</h1>

    <h2>Votre Ticket</h2>

    <p>Client en cours (Ticket - Position): 
        <c:choose>
            <c:when test="${not empty currentTicket}">
                Ticket - ${currentTicket.ticketNumber}, Position - ${currentTicket.positionInQueue}
            </c:when>
            <c:otherwise>
                Aucun ticket en cours
            </c:otherwise>
        </c:choose>
    </p>
    

    <h3>Les details de votre ticket</h3>
    <p><strong>->Numero du ticket:</strong> ${newTicket.ticketNumber}</p>
    <p><strong>->Position du ticket:</strong> ${newTicket.positionInQueue}</p>
    <p><strong>->Le nombre de personnes devant:</strong> ${peopleAhead}</p>
    <p><strong>->Service:</strong> ${newTicket.service.name}</p>
    <p><strong>->Localisation:</strong> ${newTicket.location.name}</p>
    

    <!-- Navigation links -->
    <div class="nav">
        <ul>
            <li><a href="/client_view_tickets">Voir mes tickets</a></li>
            <li><a href="/client_home">Acceuil client</a></li>
            <li><a href="/logout">Se deconnecter</a></li>
        </ul>
    </div>

</body>
</html>